package main

import (
    "fmt"
    "log"
    "github.com/quekshuy/evernote-golang-sdk/Auth"
)

// getLoginCredentials asks user for Evernote login credentials
func getLoginCredentials() (username string, password string) {

    fmt.Printf("Evernote username: ")
    fmt.Scanf("%s", &username)
    fmt.Printf("Password: ")
    fmt.Scanf("%s", &password)

    return username, password
}

// getUserAuthCode asks user for Evernote 2FA if user has it enabled.
func getUserAuthCode() (authCode string) {

    fmt.Printf("Auth code: ")
    fmt.Scanf("%s", &authCode)
    return authCode
}

func login(username string, password string, authChan chan Auth.AuthStageResult, bot *Auth.EvernoteAuthBot) {

    go bot.Login(username, password, authChan)

    // we use the select syntax 
    select {
        case result := <-authChan:
            log.Print("login received message")
            if result.Error != nil {
                handleErrors(result.Error, result.ErrorAssocObject)
            } else {
                // 2fa?
                elements := result.Elements
                log.Printf("login done: %v\n", elements)
                is2FA := result.Elements["is2FA"]
                if v, ok := is2FA.(bool); ok {
                    if v {
                        twoFACode := getUserAuthCode()
                        handle2FA(twoFACode, authChan, bot)
                    } else {
                        log.Println("No 2FA")
                        allowAccess(authChan, bot)
                    }
                }
            }
    }
}

func handleErrors(err error, obj interface{}) {
    fmt.Printf("Received error: %v, %v\n", err, obj)
}

func handle2FA(authCode string, authChan chan Auth.AuthStageResult, bot *Auth.EvernoteAuthBot) {

    log.Print("getting 2fa")
    go bot.HandleTwoFactor(authCode, authChan)

    select {
        case result := <-authChan:
            if result.Error != nil {
                handleErrors(result.Error, result.ErrorAssocObject)
            } else {
                // Pass 2FA, go to get access
                allowAccess(authChan, bot)
            }
    }
}

func allowAccess(authChan chan Auth.AuthStageResult, bot *Auth.EvernoteAuthBot) {

    log.Print("getting auth token")
    go bot.AllowAccess(bot.TempOauthToken(), authChan)

    select {
        case result:= <-authChan:
            if result.Error != nil {
                handleErrors(result.Error, result.ErrorAssocObject)
            } else {
                switch v := result.Elements["verifier"].(type) {
                    case string:
                        log.Print("getting oauth token")
                        getOauthToken(v, authChan, bot)
                    default:
                        log.Fatal("No verifier returned")
                }
            }
    }
}

func getOauthToken(verifier string, authChan chan Auth.AuthStageResult, bot *Auth.EvernoteAuthBot) {
    go bot.GetOauthToken(bot.TempOauthToken(), verifier, authChan)

    select {
        case result:=<-authChan:
            if result.Error != nil {
                handleErrors(result.Error, result.ErrorAssocObject)
            } else {
                switch v:=result.Elements["oauthToken"].(type) {
                    case string:
                        log.Printf("Got the token! %v", v)
                    default:
                        log.Fatal("Huge error, no token")
                }
            }
    }
}

func getTmpToken(authChan chan Auth.AuthStageResult, bot *Auth.EvernoteAuthBot) {
    go bot.GetTmpOauthToken(authChan)

    // wait for result
    result := <-authChan

    if result.Error != nil {
        handleErrors(result.Error, result.ErrorAssocObject)
    } else {
        // proceed to login
        username, password := getLoginCredentials()
        login(username, password, authChan, bot)
    }

}


func main() {
    bot := &Auth.EvernoteAuthBot{}
    authChan := make(chan Auth.AuthStageResult)
    getTmpToken(authChan, bot)
}
