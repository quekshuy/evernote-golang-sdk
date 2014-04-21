package auth

import (
    "fmt"
    "os"
    "github.com/mrjones/oauth"
)

// Environment variables for configuration
const (
    ENV_EVERNOTE_HOST       = "EVERNOTE_HOST"
    ENV_CONSUMER_KEY        = "EVERNOTE_API_KEY"
    ENV_CONSUMER_SECRET     = "EVERNOTE_API_SECRET"
    ENV_CALLBACK_URL        = "EVERNOTE_SERVICE_CALLBACK"
    ENV_EVERNOTE_DEBUG      = "EVERNOTE_DEBUG"
)

// URLS for request EVERNOTE service

const (
    REQUEST_TOKEN_URL       = "/oauth"
    AUTHORIZE_TOKEN_URL     = "/OAuth.action"
    ACCESS_TOKEN_URL        = "/oauth"
)


// WHOLE BUNCH OF FUNCTIONS FOR ACCESSING
// OAUTH PARAMETERS

/**

Here's the algorithm:

1) We get temporary request token from Evernote Oauth.

2) Store request token in database.

3) User redirected back to our server via callback with temp token as key and verification
code. (oauth_token and oauth_verifier).

4) We use the oauth_token and oauth_verifier in another request to get the access token,
    the NoteStore URL and the edam user ID.

5) access token is what we will use in subsequent requests to the cloud API

*/

func GetOauthConsumer(reqTokenUri string, authTokenUri string, accessTokenUri string, debugMode bool) *oauth.Consumer {

        consumerKey := os.Getenv(ENV_CONSUMER_KEY)
        consumerSecret := os.Getenv(ENV_CONSUMER_SECRET)

        fmt.Println("consumerKey = ", consumerKey, ", secret = ", consumerSecret)

        c := oauth.NewConsumer(
            consumerKey,
            consumerSecret,
            oauth.ServiceProvider{
                RequestTokenUrl: reqTokenUri,
                AuthorizeTokenUrl: authTokenUri,
                AccessTokenUrl: accessTokenUri,
            })

        c.Debug(debugMode)
        return c
}


// GetEvernoteTempRequestToken will authenticate with Evernote
// and return the temporary token.
func GetEvernoteTempRequestToken(host string) (string, string, error) {


    shouldDebug := false
    // if not specified, Getenv returns empty string
    if os.Getenv(ENV_EVERNOTE_DEBUG) == "true" {
       shouldDebug = true
    }

    c := GetOauthConsumer(
            host + REQUEST_TOKEN_URL,
            host + AUTHORIZE_TOKEN_URL,
            host + ACCESS_TOKEN_URL,
            shouldDebug)

    fmt.Println("Got consumer")

    requestToken, url, err := c.GetRequestTokenAndUrl(os.Getenv(ENV_CALLBACK_URL))
    return requestToken.Token, url, err
}



