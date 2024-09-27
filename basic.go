/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package slack_plugin_seddon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	
	"github.com/SeddonShen/slack_plugin_seddon/i18n"
	"github.com/apache/incubator-answer-plugins/util"
	"github.com/apache/incubator-answer/plugin"
	"github.com/gin-gonic/gin"
)

//go:embed  info.yaml
var Info embed.FS

type Importer struct {
}

type SlackUserResponse struct {
	Ok   bool `json:"ok"`
	User struct {
		Profile struct {
			Email string `json:"email"`
		} `json:"profile"`
	} `json:"user"`
}

func init() {
	plugin.Register(&Importer{})
}

func (ip *Importer) Info() plugin.Info {
	info := &util.Info{}
	info.GetInfo(Info)

	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    info.SlugName,
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      info.Author,
		Version:     info.Version,
		Link:        info.Link,
	}
}

func parseText(text string) (string, string, []string, error) {
	re := regexp.MustCompile(`\[(.*?)\]`)
	matches := re.FindAllStringSubmatch(text, -1)

	if len(matches) != 3 {
		return "", "", nil, fmt.Errorf("text field does not conform to the required format")
	}

	part1 := matches[0][1]
	part2 := matches[1][1]
	rawTags := strings.Split(matches[2][1], ",")

	var tags []string
	for _, tag := range rawTags {
		if tag != "" {
			tags = append(tags, tag)
		}
	}

	// if part1 or part2 or tags in empty return error
	println(part1, part2, tags)
	println(len(tags))
	if part1 == "" || part2 == "" || len(tags) == 0 {
		return "", "", nil, fmt.Errorf("text field does not be empty")
	}
	return part1, part2, tags, nil
}
func getSlackUserEmail(userID, token string) (string, error) {
	url := fmt.Sprintf("https://slack.com/api/users.info?user=%s", userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var userResponse SlackUserResponse
	if err := json.Unmarshal(body, &userResponse); err != nil {
		return "", err
	}

	if !userResponse.Ok {
		return "", fmt.Errorf("failed to get user info from Slack")
	}

	return userResponse.User.Profile.Email, nil
}

const slackSigningSecret = "32bitxxxx" // 请在部署时将此值设置为环境变量
func verifySlackRequest(ctx *gin.Context) error {
	body, err := io.ReadAll(ctx.Request.Body)
	fmt.Println("Body:", string(body))
	if err != nil {
		return fmt.Errorf("could not read request body: %v", err)
	}
	timestamp := ctx.GetHeader("X-Slack-Request-Timestamp")
	slackSignature := ctx.GetHeader("X-Slack-Signature")

	fmt.Println("Received request:", ctx)
	fmt.Println("Timestamp:", timestamp)
	fmt.Println("Signature:", slackSignature)
	// check the timestamp validity in 5 minutes
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %v", err)
	}
	if time.Now().Unix()-ts > 60*5 {
		return fmt.Errorf("timestamp is too old")
	}
	fmt.Println("Body:", string(body))
	// 重新设置请求体，以便后续处理
	ctx.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	// 构建签名基字符串
	sigBaseString := fmt.Sprintf("v0:%s:%s", timestamp, string(body))

	// 使用HMAC SHA256算法计算签名
	h := hmac.New(sha256.New, []byte(slackSigningSecret))
	h.Write([]byte(sigBaseString))
	computedSignature := "v0=" + hex.EncodeToString(h.Sum(nil))

	fmt.Println("sigBaseString:", sigBaseString)
	fmt.Println("computedSignature:", computedSignature)
	fmt.Println("slackSignature:", slackSignature)
	// 比较计算出的签名和请求中的签名
	if !hmac.Equal([]byte(computedSignature), []byte(slackSignature)) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
func (ip *Importer) GetQuestion(ctx *gin.Context) (questionInfo *plugin.QuestionImporterInfo, err error) {
	questionInfo = &plugin.QuestionImporterInfo{}
	fmt.Println("GetQuestion123")
	fmt.Println(ctx.Request)

	// 验证Slack请求
	err = verifySlackRequest(ctx)
	if err != nil {
		return nil, err
	}

	cmd := ctx.PostForm("command")
	fmt.Println(cmd)
	fmt.Println("team_domain", ctx.PostForm("team_domain"))
	fmt.Println("token", ctx.PostForm("token"))
	fmt.Println("text", ctx.PostForm("text"))
	fmt.Println("user_id", ctx.PostForm("user_id"))

	text := ctx.PostForm("text")
	part1, part2, tags, err := parseText(text)
	if err != nil {
		return questionInfo, err
	}

	fmt.Println("Part 1:", part1)
	fmt.Println("Part 2:", part2)
	fmt.Println("Tags:", tags)

	questionInfo.Title = part1
	questionInfo.Content = part2
	questionInfo.Tags = tags
	userID := ctx.PostForm("user_id")

	token := "xoxb-xxxx"
	email, err := getSlackUserEmail(userID, token)
	if err != nil {
		return questionInfo, err
	}

	fmt.Println("User Email:", email)
	questionInfo.UserEmail = email

	return questionInfo, nil
}
