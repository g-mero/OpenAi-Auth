package openai_auth

import (
	"errors"
	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
)

var (
	preAuthGetApi = "https://ai.fakeopen.com/auth/preauth"
)

func getPreAuthCode() (string, error) {
	client := req.C()

	resp, err := client.R().Get(preAuthGetApi)

	if err != nil {
		return "", err
	}

	if resp.IsErrorState() {
		return "", errors.New("请求失败：" + resp.Status)
	}

	preAuth := gjson.Get(resp.String(), "preauth_cookie")

	if preAuth.Exists() {
		return preAuth.String(), nil
	}

	return "", errors.New("json获取失败")
}
