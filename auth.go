package openai_auth

import (
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"strconv"
	"strings"
	"time"
)

type Error struct {
	Location   string
	StatusCode int
	Details    string
	Error      error
}

func NewError(location string, statusCode int, details string, err error) *Error {
	return &Error{
		Location:   location,
		StatusCode: statusCode,
		Details:    details,
		Error:      err,
	}
}

type Authenticator struct {
	email         string
	password      string
	accessToken   string
	expireAt      int64 // UTC unix Seconds
	refreshToken  string
	codeVerifier  string
	codeChallenge string
	client        *req.Client
}

func NewAuth(email, password string) *Authenticator {
	auth := &Authenticator{
		email:         email,
		password:      password,
		accessToken:   "",
		refreshToken:  "",
		expireAt:      0,
		codeVerifier:  "3Pujyh3iJ_6DKq4uPm86mBFnaeE-iEhmXzWtgmPOqgs",
		codeChallenge: "XMAIUK-Q1VqXJ6lmIeT0imDkzeVKD_ask1VNO7V4dE0",
	}

	client := req.C().
		SetUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" +
			" AppleWebKit/537.36 (KHTML, like Gecko) " + "Chrome/109.0.0.0 Safari/537.36").
		SetRedirectPolicy(req.NoRedirectPolicy()).DevMode()

	auth.client = client

	return auth
}

func (that *Authenticator) Auth() *Error {
	preAuth, err := getPreAuthCode()
	if err != nil {
		return NewError("part1", 500,
			"error when try to get pre_auth", err)
	}

	return that.part2(preAuth)
}

func (that *Authenticator) part2(preAuth string) *Error {
	url := "https://auth0.openai.com/authorize?client_id=pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh&audience=https%3A%2F" +
		"%2Fapi.openai.com%2Fv1&redirect_uri=com.openai.chat%3A%2F%2Fauth0.openai.com%2Fios%2Fcom.openai.chat" +
		"%2Fcallback&scope=openid%20email%20profile%20offline_access%20model.request%20model.read" +
		"%20organization.read%20offline&response_type=code&code_challenge=" + that.codeChallenge +
		"&code_challenge_method=S256&prompt=login&preauth_cookie=" + preAuth

	resp, err := that.client.R().SetHeader("Referer", "https://ios.chat.openai.com/").Get(url)
	if err != nil {
		return NewError("part2", 500, "error when send requeset to login url", err)
	}

	if resp.IsErrorState() {
		return NewError("part2", resp.StatusCode, "error when send requeset to login url", nil)
	}

	// 获取跳转到的地址
	location, err := resp.Location()
	if err != nil {
		return NewError("part2", 500, "error when send get redirect url", err)
	}

	return that.part3(location.Query().Get("state"))
}

func (that *Authenticator) part3(state string) *Error {
	url := "https://auth0.openai.com/u/login/identifier?state=" + state
	data := `{
            "state": ` + strconv.Quote(state) + `,
            "username": ` + strconv.Quote(that.email) + `,
            "js-available": true,
            "webauthn-available": true,
            "is-brave": false,
            "webauthn-platform-available": false,
            "action": "default"
        }`

	resp, err := that.client.R().SetHeaders(map[string]string{"Referer": url, "Origin": "https://auth0.openai.com"}).
		SetBodyJsonString(data).Post(url)
	if err != nil {
		return NewError("part3", 500, "error when send request to identifier", err)
	}

	if resp.StatusCode == 302 {
		return that.part4(state)
	}

	return NewError("part3", resp.StatusCode, resp.Status, nil)
}

func (that *Authenticator) part4(state string) *Error {
	url := "https://auth0.openai.com/u/login/password?state=" + state
	data := `{
            "state": ` + strconv.Quote(state) + `,
            "username": ` + strconv.Quote(that.email) + `,
            "password": ` + strconv.Quote(that.password) + `,
            "action": "default"
        }`

	resp, err := that.client.R().SetHeaders(map[string]string{"Referer": url, "Origin": "https://auth0.openai.com"}).
		SetBodyJsonString(data).Post(url)

	if err != nil {
		return NewError("part4", 500, "error when send request to password", err)
	}

	if resp.StatusCode == 400 {
		return NewError("part4", 400, "wrong email or password", nil)
	}

	if resp.StatusCode == 302 {
		location, err := resp.Location()
		if err != nil || !strings.Contains(location.Path, "/authorize/resume") {
			return NewError("part4", 500, "Login Fail", nil)
		}
		return that.part5(location.String(), url)
	}

	return NewError("part4", 500, "Error Login", nil)
}

func (that *Authenticator) part5(url, ref string) *Error {
	resp, err := that.client.R().SetHeader("Referer", ref).Get(url)

	if err != nil {
		return NewError("part5", 500, "request failed", err)
	}

	if resp.StatusCode == 302 {
		location, err := resp.Location()

		if err != nil || !strings.Contains(location.String(), "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback") {
			fmt.Println(location.Path)
			return NewError("part5", 500, "failed check location", nil)
		}
		// 获取code
		code := location.Query().Get("code")
		if code == "" {
			return NewError("part5", 500, "failed get code", nil)
		}
		return that.getToken(code)
	}

	return NewError("part5", 500, "failed Login", nil)
}

func (that *Authenticator) getToken(code string) *Error {
	url := "https://auth0.openai.com/oauth/token"

	data := `{
	"redirect_uri": "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
    "grant_type": "authorization_code",
    "client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
    "code": ` + strconv.Quote(code) + `,
    "code_verifier": ` + strconv.Quote(that.codeVerifier) + `
	}`

	resp, err := that.client.R().SetBodyJsonString(data).Post(url)
	if err != nil {
		return NewError("getToken", 500, "failed request", nil)
	}

	if resp.IsSuccessState() {
		accessToken := gjson.Get(resp.String(), "access_token")
		refreshToken := gjson.Get(resp.String(), "refresh_token")
		expireIn := gjson.Get(resp.String(), "expires_in")

		if accessToken.Exists() && refreshToken.Exists() && expireIn.Exists() {
			that.refreshToken = refreshToken.String()
			that.accessToken = accessToken.String()
			// 提前5分钟
			that.expireAt = time.Now().Unix() + expireIn.Int() - 5*60

			return nil
		}
	}

	return NewError("getToken", resp.StatusCode, "response data get failed", nil)
}

func (that *Authenticator) GetAccessToken() string {
	return that.accessToken
}
