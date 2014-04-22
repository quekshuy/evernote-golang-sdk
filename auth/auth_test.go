package auth

import (
	"fmt"
	"testing"
)

func TestGetEvernoteTempRequestToken(t *testing.T) {
	host := "https://sandbox.evernote.com"
	token, url, err := GetEvernoteTempRequestToken(host)
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
