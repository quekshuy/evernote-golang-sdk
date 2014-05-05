package Auth

import (
    "log"
	"github.com/mrjones/oauth"
	"os"
)

// Environment variables for configuration
const (
	ENV_EVERNOTE_HOST   = "EVERNOTE_HOST"
	ENV_CONSUMER_KEY    = "EVERNOTE_API_KEY"
	ENV_CONSUMER_SECRET = "EVERNOTE_API_SECRET"
	ENV_CALLBACK_URL    = "EVERNOTE_SERVICE_CALLBACK"
	ENV_EVERNOTE_DEBUG  = "EVERNOTE_DEBUG"
)

// URLS for request EVERNOTE service

const (
	REQUEST_TOKEN_URL   = "/oauth"
	AUTHORIZE_TOKEN_URL = "/OAuth.action"
	ACCESS_TOKEN_URL    = "/oauth"
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

// GetOauthConsumer will return a consumer given a set of URLs
func GetOauthConsumer(reqTokenUri string, authTokenUri string, accessTokenUri string, debugMode bool) *oauth.Consumer {

	consumerKey := os.Getenv(ENV_CONSUMER_KEY)
	consumerSecret := os.Getenv(ENV_CONSUMER_SECRET)

	log.Println("consumerKey = ", consumerKey, ", secret = ", consumerSecret)

    // Error check, if environment variables don't exist
    if consumerKey == "" || consumerSecret == "" {
        log.Fatal("No evernote consumer key or secret")
    }

	c := oauth.NewConsumer(
		consumerKey,
		consumerSecret,
		oauth.ServiceProvider{
			RequestTokenUrl:   reqTokenUri,
			AuthorizeTokenUrl: authTokenUri,
			AccessTokenUrl:    accessTokenUri,
		})

	c.Debug(debugMode)
	return c
}

// GetEvernoteTempRequestToken will authenticate with Evernote
// and return the temporary token and the secret.
func GetEvernoteTempRequestToken(evernoteHost string, redirectUri string, isSandbox bool) (string, string, string, *oauth.Consumer, error) {

	c := GetOauthConsumer(
		evernoteHost + REQUEST_TOKEN_URL,
		evernoteHost + AUTHORIZE_TOKEN_URL,
		evernoteHost + ACCESS_TOKEN_URL,
		isSandbox)

	requestToken, url, err := c.GetRequestTokenAndUrl(redirectUri)
	return requestToken.Token, requestToken.Secret, url, c, err
}

// GetEvernoteAccessToken returns the access token, the secret and any additional data.
// We basically decompose the oauth.AccessToken struct that is returned.
func GetEvernoteAccessToken(evernoteHost string, requestToken string, requestSecret string, verifier string, isSandbox bool) (string, string, map[string]string, error) {

	c := GetOauthConsumer(
		evernoteHost + REQUEST_TOKEN_URL,
		evernoteHost + AUTHORIZE_TOKEN_URL,
		evernoteHost + ACCESS_TOKEN_URL,
		isSandbox)
	accessToken, err := c.AuthorizeToken(
		&oauth.RequestToken{
			Token:  requestToken,
			Secret: requestSecret,
		}, verifier)

	if err != nil {
		log.Printf("Could not get access token from evernote: %v", err)
	}
	return accessToken.Token, accessToken.Secret, accessToken.AdditionalData, err
}
