package main

import (
    "github.com/quekshuy/evernote-golang-sdk/Auth"
)

func main() {
    bot := &Auth.EvernoteAuthBot{}
    bot.GetToken()
}
