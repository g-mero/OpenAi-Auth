package openai_auth

import (
	"errors"
	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"strconv"
	"strings"
	"time"
)

type Authenticator struct {
	email         string
	password      string
	AccessToken   string
	ExpireAt      int64 // UTC unix Seconds
	refreshToken  string
	codeVerifier  string
	codeChallenge string
	client        *req.Client
}

func NewAuth(email, password string) *Authenticator {
	auth := &Authenticator{
		email:         email,
		password:      password,
		AccessToken:   "",
		refreshToken:  "",
		ExpireAt:      0,
		codeVerifier:  "3Pujyh3iJ_6DKq4uPm86mBFnaeE-iEhmXzWtgmPOqgs",
		codeChallenge: "XMAIUK-Q1VqXJ6lmIeT0imDkzeVKD_ask1VNO7V4dE0",
	}

	client := req.C().
		SetUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" +
			" AppleWebKit/537.36 (KHTML, like Gecko) " + "Chrome/109.0.0.0 Safari/537.36").
		SetRedirectPolicy(req.NoRedirectPolicy())

	auth.client = client

	return auth
}

// Auth this will fire the auth process
func (that *Authenticator) Auth() error {
	preAuth, err := getPreAuthCode()
	if err != nil {
		return errors.New("error at part1：" + err.Error())
	}

	return that.part2(preAuth)
}

func (that *Authenticator) part2(preAuth string) error {
	url := "https://auth0.openai.com/authorize?client_id=pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh&audience=https%3A%2F" +
		"%2Fapi.openai.com%2Fv1&redirect_uri=com.openai.chat%3A%2F%2Fauth0.openai.com%2Fios%2Fcom.openai.chat" +
		"%2Fcallback&scope=openid%20email%20profile%20offline_access%20model.request%20model.read" +
		"%20organization.read%20offline&response_type=code&code_challenge=" + that.codeChallenge +
		"&code_challenge_method=S256&prompt=login&preauth_cookie=" + preAuth

	resp, err := that.client.R().SetHeader("Referer", "https://ios.chat.openai.com/").Get(url)
	if err != nil {
		return errors.New("part2: error when send request to login url")
	}

	if resp.IsErrorState() {
		return errors.New("part2: error response: " + resp.Status)
	}

	// 获取跳转到的地址
	location, err := resp.Location()
	if err != nil {
		return errors.New("part2: location error" + err.Error())
	}

	return that.part3(location.Query().Get("state"))
}

func (that *Authenticator) part3(state string) error {
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
		return errors.New("part3: error when send request to identifier")
	}

	if resp.StatusCode == 302 {
		return that.part4(state)
	}

	return errors.New("part3: error " + resp.Status)
}

func (that *Authenticator) part4(state string) error {
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
		return errors.New("part4: error to request")
	}

	if resp.StatusCode == 400 {
		return errors.New("part4: wrong email or password")
	}

	if resp.StatusCode == 302 {
		location, err := resp.Location()
		if err != nil || !strings.Contains(location.Path, "/authorize/resume") {
			return errors.New("part4 Login Fail")
		}
		return that.part5(location.String(), url)
	}

	return errors.New("part4 Login Fail")
}

func (that *Authenticator) part5(url, ref string) error {
	resp, err := that.client.R().SetHeader("Referer", ref).Get(url)

	if err != nil {
		return errors.New("part5: error to request")
	}

	if resp.StatusCode == 302 {
		location, err := resp.Location()

		if err != nil || !strings.Contains(location.String(), "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback") {
			return errors.New("part5: failed check location")
		}
		// 获取code
		code := location.Query().Get("code")
		if code == "" {
			return errors.New("part5: failed get code")
		}
		return that.getToken(code)
	}

	return errors.New("part5: failed login")
}

func (that *Authenticator) getToken(code string) error {
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
		return errors.New("getToken: error to request")
	}

	if resp.IsSuccessState() {
		accessToken := gjson.Get(resp.String(), "access_token")
		refreshToken := gjson.Get(resp.String(), "refresh_token")
		expireIn := gjson.Get(resp.String(), "expires_in")

		if accessToken.Exists() && refreshToken.Exists() && expireIn.Exists() {
			that.refreshToken = refreshToken.String()
			that.AccessToken = accessToken.String()
			// 5 minutes earlier
			that.ExpireAt = time.Now().Unix() + expireIn.Int() - 5*60

			return nil
		}
	}

	return errors.New("getToken: response data get failed")
}

// GetRefreshToken do not expose your refreshToken, it's dangerous!
func (that *Authenticator) GetRefreshToken() string {
	return that.refreshToken
}

// RenewAccessTokenByRefreshToken get accessToken by refreshToken
func RenewAccessTokenByRefreshToken(refreshToken string) (string, error) {
	url := "https://auth0.openai.com/oauth/token"

	client := req.C().
		SetUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" +
			" AppleWebKit/537.36 (KHTML, like Gecko) " + "Chrome/109.0.0.0 Safari/537.36").
		SetRedirectPolicy(req.NoRedirectPolicy())

	data := `{
		"redirect_uri": "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
		"grant_type": "refresh_token",
		"client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
		"refresh_token": ` + strconv.Quote(refreshToken) + `
	}`

	resp, err := client.R().SetBodyJsonString(data).Post(url)
	if err != nil {
		return "", errors.New("error send refresh token request")
	}

	if resp.IsSuccessState() {
		token := gjson.Get(resp.String(), "access_token")

		if !token.Exists() {
			return "", errors.New("bad json")
		}
		return token.String(), nil
	}

	return "", errors.New("error request: " + resp.Status)

}
