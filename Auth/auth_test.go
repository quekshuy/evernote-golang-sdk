package Auth

import (
	"fmt"
    "os"
	"testing"
)

// TestGetTmpOauthToken will first get the tmp oauth token.
// We may need to set environment variables before we do this.
func TestGetTmpOauthToken(t *testing.T) {

    // Set that we are using sandbox
    os.Setenv(ENV_IS_SANDBOX, "true")
    bot := &EvernoteAuthBot{}

    if tmpToken, err := bot.GetTmpOauthToken(); err != nil {
        t.Fatalf("error: %v", err)
    } else if tmpToken  == ""{
        t.Fatalf("tmp token not issued")
    }

    if bot.tmpOauthToken == "" {
        // error, it should be set
        t.Fatal("No tmp oauth token detected")
    }
}

func TestWholeOauthFlow(t *testing.T) {

    bot := &EvernoteAuthBot{}
    bot.GetToken()

    if bot.oauthToken == "" {
        t.Fatal("no oauth token after flow completed")
    }
}

func TestGetEvernoteTempRequestToken(t *testing.T) {

	host := "https://sandbox.evernote.com"
    // TODO: test for secret (which is now a throwaway variable)
    token, _, url, _, err := GetEvernoteTempRequestToken(host, host, true)
	if err != nil {
		fmt.Println("Error occurred: ", err)
	} else {
		if token == "" {
			fmt.Println("Token is nil")
		} else {
			fmt.Println("Token = ", token)
		}

		if url == "" {
			fmt.Println("url is nil")
		} else {
			fmt.Println("url is not nil = ", url)
		}
	}
}
