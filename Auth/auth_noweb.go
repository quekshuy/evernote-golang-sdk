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
    "log"
    "bytes"
    "strconv"
    "time"
    "os"
    "strings"
    "io/ioutil"
    "net/http"
    "net/url"

    "code.google.com/p/go-uuid/uuid"
)

// CONSTANTS
const (
    ENV_API_KEY = "EVERNOTE_API_KEY"
    ENV_API_SECRET = "EVERNOTE_API_SECRET"
    ENV_IS_SANDBOX = "EVERNOTE_IS_SANDBOX"
)



// EvernoteAuthBot will do the authentication via
// HTTP requests, storing state as it does so.
// Basically, it does the required HTTP requests as if you were logging 
// into Evernote on the web.
type EvernoteAuthBot struct {
    cookies []*http.Cookie
    formData map[string]url.Values
    username string
    password string
    tmpOauthToken string
    verifierToken string
    oauthToken string
    code string
    incorrectLogins int
    incorrectCodes int
}

// Our own error type
type BotError struct {
    Message string
    IsRedirect bool
}

func (e *BotError) Error() string {
    return e.Message
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
    /*log.Printf("API Key = %s, API Secret = %s", key, secret)*/
    return key, secret, err
}

func (bot *EvernoteAuthBot) PostData() map[string]url.Values {
    if bot.formData == nil {

        bot.formData = map[string]url.Values{
            "login": url.Values{
                "login": []string{"Sign in"},
            },
            "access": url.Values{
                "authorize": []string{"Authorize"},
            },
            "tfa": {
                "login": []string{"Sign in"},
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
        base = "sandbox.evernote.com"
    } else {
        base = "www.evernote.com"
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

// redirectPolicy is our CheckRedirect function. On a redirect, it will 
// return a custom BotError with IsRedirect set to true.
func redirectPolicy(req *http.Request, via []*http.Request) error {
    return &BotError{ IsRedirect: true, Message: "Redirect detected" }
}

// LoadPage sends HTTP requests and does some minimal parsing of the response. At this point
// this means we extract the cookies. Only handles GET and POST requests as of now.
func (bot *EvernoteAuthBot) LoadPage(uri string, method string, params url.Values) (*http.Response, error) {
    var req *http.Request
    var resp *http.Response
    var err error

    /*log.Printf("LoadPage: uri = %s, method = %s, values = %v", uri, method, params)*/

    client := &http.Client{
        CheckRedirect: redirectPolicy,
    }
    if method == "GET" {
        req, err = http.NewRequest(method, uri + "?" + params.Encode(), nil)
    } else if method == "POST" {
        req, err = http.NewRequest(method, uri, bytes.NewBufferString(params.Encode()))
        req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Add("Content-Length", strconv.Itoa(len(params.Encode())))
        // TODO: might need to set the content-length here
    }

    if err != nil {
        log.Fatalf("Error trying to set up request: %v", err)
    }

    // Cookies baby, cookies
    for _, cookie := range bot.cookies {
        req.AddCookie(cookie)
    }

    resp, err = client.Do(req)
    log.Printf("request: %v\n", req)

    if err != nil {
        if e, yes := isBotError(err); yes && e.IsRedirect {
            err = nil
        }
    }

    if err == nil {
        bot.cookies = resp.Cookies()
    }

    return resp, err
}

func (bot *EvernoteAuthBot) tokenRequestData(addData url.Values) url.Values {

    var key, secret string

    v := url.Values{}

    key, secret, err := bot.ApiCredentials()
    if err != nil {
        log.Fatalf("No Evernote consumer key/secret set: %s/%s", key, secret)
    }

    /*log.Printf("tokenRequestData: key = %s, secret = %s", key, secret)*/

    v.Set("oauth_consumer_key", key)
    v.Set("oauth_signature", secret + "%26")
    v.Set("oauth_signature_method", "PLAINTEXT")
    v.Set("oauth_timestamp", strconv.Itoa(int(time.Now().Unix())))
    v.Set("oauth_nonce", strings.Replace(uuid.New(), "-", "", -1))

    for key, li := range addData {
        for _, inner := range li {
            v.Add(key, inner)
        }
    }

    return v
}

func (bot * EvernoteAuthBot) GetToken() {
    fmt.Println("Authorize...")
    bot.GetTmpOauthToken()

    bot.Login()

    fmt.Println("Allow access...")
    bot.AllowAccess()

    fmt.Println("Getting Token...")
    bot.GetOauthToken()

}

// GetTmpOauthToken will query for the initial temporary oauth token
// that evernote requests for the authentication process to proceed.
func (bot *EvernoteAuthBot) GetTmpOauthToken() (tmpToken string, err error) {

    urls := bot.urls()
    params := url.Values{"oauth_callback": []string{"https://" + urls["base"]}}

    resp, err := bot.LoadPage(
        "https://" + urls["base"] + urls["token"],
        "GET",
        bot.tokenRequestData(params),
    )

    if err != nil {

        log.Printf("Error requesting temp oauth token: %v", err)

    } else if resp.StatusCode == 200 {

        if bodyBytes, err := ioutil.ReadAll(resp.Body); err == nil  {

            body := string(bodyBytes)

            if tokens, err := url.ParseQuery(body); err == nil {
                tmpToken = tokens.Get("oauth_token")
                /*log.Printf("oauth retrieved: %v", tmpToken)*/
                bot.tmpOauthToken = tmpToken
            }
        }
    } else {
        err = errors.New("Evernote Temp OAuth phase failed: " + strconv.Itoa(resp.StatusCode))
    }
    return tmpToken, err
}

// Cookie returns a *http.Cookie that has a Name matching the name argument
// which was set in the process of authentication.
func (bot *EvernoteAuthBot) Cookie(name string) *http.Cookie{
    for _, c := range bot.cookies {
        if c.Name == name {
            return c
        }
    }
    return nil
}

// Login prompts user for credentials (including 2FA). Exits if invalid
// credentials provided.
func (bot *EvernoteAuthBot) Login() {

    urls := bot.urls()
    params := url.Values{ "oauth_token": []string{bot.tmpOauthToken }}

    resp, err := bot.LoadPage(
        "https://" + urls["base"] + urls["login"],
        "GET",
        bot.tokenRequestData(params),
    )

    if err != nil {
        log.Printf("Error getting login page: %v", err)
    } else if resp.StatusCode != 200 {
        log.Fatalf("Unexpected response status on login 200 != %d", resp.StatusCode)
    }

    sessionCookie := bot.Cookie("JSESSIONID")
    if sessionCookie == nil {
        log.Fatalf("Not found JSESSIONID cookie in response")
    }

    username, password := getLoginCredentials()
    postData := bot.PostData()["login"]
    postData.Set("username", username)
    postData.Set("password", password)
    postData.Set("targetUrl", fmt.Sprintf(urls["oauth"], bot.tmpOauthToken))

    resp, err = bot.LoadPage(
        "https://" + urls["base"] + urls["login"] + ";jsessionid=" + sessionCookie.Value,
        "POST",
        postData,
    )

    if err != nil {
        log.Fatalf("Login failed: %v", err)
    }

    loc := resp.Header.Get("Location")
    // Error in login credentials
    if resp.StatusCode == 200 && loc == "" {
        if bot.incorrectLogins < 3 {
            fmt.Println("Sorry, incorrect username or password")
            bot.incorrectLogins += 1
            bot.Login()
        } else {
            log.Fatal("Incorrect login or password")
        }
    }

    if loc == "" {
        log.Fatal("Target URL was not found in the response on login")
    }

    if resp.StatusCode == 302 && strings.Contains(loc, "OTCAction") {
        bot.HandleTwoFactor()
    }

    log.Print("Success authorize, redirect to access page")
}

// HandleTwoFactor will ask user for 2FA code before proceeding to request
// for access
func (bot *EvernoteAuthBot) HandleTwoFactor() {

    urls := bot.urls()
    authCode := getUserAuthCode()
    postData := bot.PostData()["tfa"]

    postData.Set("code", authCode)
    sessionCookie := bot.Cookie("JSESSIONID")
    if sessionCookie == nil {
        log.Fatal("No JSESSIONID cookie after login")
    }

    resp, err := bot.LoadPage(
        "https://" + urls["base"] + urls["tfa"] + ";jsessionid=" + sessionCookie.Value,
        "POST",
        postData,
    )

    if err != nil {
        log.Fatalf("HandleTwoFactor: %v", err)
    }

    loc := resp.Header.Get("Location")
    if loc == "" && resp.StatusCode == 200 {
        if bot.incorrectCodes < 3 {
            fmt.Println("Sorry, incorrect 2 factor code")
            bot.incorrectCodes += 1
            bot.HandleTwoFactor()
        } else {
            log.Fatal("Incorrect 2 factor code")
        }
    }

    if loc == "" {
        log.Fatal("Target URL was not found in response on 2-factor login")
    }
}

func (bot *EvernoteAuthBot) AllowAccess() {

    urls := bot.urls()

    access := bot.PostData()["access"]
    access.Set("oauth_token", bot.tmpOauthToken)
    access.Set("oauth_callback",  "https://" + urls["base"])

    resp, err := bot.LoadPage(
        "https://" + urls["base"] + urls["access"],
        "POST",
        access,
    )

    if err != nil {
        log.Fatalf("Error AllowAccess: %v", err)
    }

    if resp.StatusCode != 302 {
        log.Fatalf("Unexpected response status on allowing access 302 != %d", resp.StatusCode)
    }

    loc := resp.Header.Get("Location")
    if loc != "" {
        parts := strings.Split(loc, "?")

        if len(parts) > 1 {

            paramPart := parts[1]
            params, err := url.ParseQuery(paramPart)
            if err != nil {
                log.Fatalf("error parsing allow access: %v", err)
            }

            verifier := params.Get("oauth_verifier")

            if verifier == "" {
                log.Fatal("Verifier not found")
            } else {
                bot.verifierToken = verifier
                log.Println("Verifier token taken")
            }
        }
    }
}

func (bot *EvernoteAuthBot) GetOauthToken() (string, error) {
    urls := bot.urls()
    params := url.Values{ "oauth_token": []string{ bot.tmpOauthToken},
        "oauth_verifier": []string{ bot.verifierToken },
    }

    resp, err := bot.LoadPage(
        "https://" + urls["base"] + urls["token"],
        "GET",
        bot.tokenRequestData(params),
    )

    if err != nil {
        log.Fatalf("Error getting oauth token: %v", err)
    }
    if resp.StatusCode != 200 {
        log.Fatalf("Unexpected response status on getting oauth status token 200 != %d", resp.StatusCode)
    }

    if bodyBytes, err := ioutil.ReadAll(resp.Body); err != nil {
        return "", err
    } else {
        body := string(bodyBytes)
        data, err := url.ParseQuery(body)
        if err != nil {
            return "", err
        }
        token := data.Get("oauth_token")
        if token == "" {
            log.Fatalf("Error, no oauth token in returned response: %v", data)
        }
        bot.oauthToken = token
        return token, nil
    }
    return "", nil
}


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

// isBotError used to check errors returned by client.Do() calls.
// These errors might be errors thrown by our redirectPolicy function (used in 
// the client).
func isBotError(e error) (*BotError, bool) {
    switch t := e.(type) {
        case *url.Error:
            return isBotError(t.Err)
        case *BotError:
            return t, true
        default:
            return nil, false
    }
}





