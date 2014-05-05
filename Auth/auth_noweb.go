/*

auth_noweb.go contains code that allows for authentication with Evernote
without having to go through a web-server. 

Based on the code in geeknote (https://github.com/VitaliyRodnenko/geeknote/blob/master/geeknote/oauth.py)

Ported from Python to golang.

*/

package Auth

import (
    "errors"
    "fmt"
    "os"
)

// CONSTANTS
const (
    ENV_API_KEY = "EVERNOTE_API_KEY"
    ENV_API_SECRET = "EVERNOTE_API_SECRET"
    ENV_IS_SANDBOX = "EVERNOTE_IS_SANDBOX"
)



// EvernoteAuther will do the authentication via
// HTTP requests, storing state as it does so.
// Basically, it does the required HTTP requests as if you were logging 
// into Evernote on the web.
type EvernoteAuthBot struct {
    cookies map[string]string
    formData map[string]map[string]string
    username string
    password string
    tmpOauthToken string
    verifierToken string
    oauthToken string
    code string
}

// ApiCredentials will get the API key and secret from environment variables.
// This library relies on environment variables to pull out 
func (bot *EvernoteAuthBot) ApiCredentials() (string, string, error) {

    key := os.Getenv(ENV_API_KEY)
    secret := os.Getenv(ENV_API_SECRET)

    var err error

    if key == "" {
        err = errors.New(ENV_API_KEY + " not set")
    } else if secret == "" {
        err = errors.New(ENV_API_SECRET + " not set")
    }
    return key, secret, err
}

func (bot *EvernoteAuthBot) postData() map[string]map[string]string {
    if bot.formData == nil {

        bot.formData = map[string]map[string]string {
            "login": map[string]string {
                "login": "Sign in",
                "username": "",
                "password": "",
                "targetUrl": "",
            },
            "access": map[string]string {
                "authorize": "Authorize",
                "oauth_token": "",
                "oauth_callback": "",
                "embed": "false",
            },
            "tfa": {
                "code": "",
                "login": "Sign in",
            },
        }
    }
    return bot.formData
}

// Urls gets a map of URLS that represent the steps in the authentication 
// process.
func (bot *EvernoteAuthBot) urls() map[string]string {

    var base string

    is_sandbox := os.Getenv(ENV_IS_SANDBOX)
    if is_sandbox != "" {
        base := "sandbox.evernote.com"
    } else {
        base := "www.evernote.com"
    }

    return map[string]string {
        "base":  base,
        "oauth": "/OAuth.action?oauth_token=%s",
        "access": "/OAuth.action",
        "token": "/oauth",
        "login": "/Login.action",
        "tfa": "/OTCAuth.action",
    }
}



