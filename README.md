## OpenAi-Auth
OpenAi-Auth is a Golang library that provides authentication for ChatGpt Web access. 
It facilitates obtaining access tokens by request to OpenAi's ios oauth system. Before
using, make sure your network is able to access OpenAi.

## Usage
To use OpenAi-Auth in your Go project:

You should get this lib first
`go get -u github.com/g-mero/openai-auth`

```go
import "github.com/g-mero/openai-auth"

auth := openai-auth.NewAuth("yourEmail", "yourPassword")

if auth.Auth() == nil {
    fmt.Println(auth.GetAccessToken())
}
```

## Inspiration
OpenAi-Auth is inspired by [Pandora](https://github.com/pengzhile/pandora)'s authentication 
approach and structure from [OpenAIAuth](https://github.com/acheong08/OpenAIAuth).