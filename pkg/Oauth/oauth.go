package Oauth


import (
	"github.com/markbates/goth/providers/google"
	"golang.org/x/oauth2"
)


var (
	Oauth2Config = &oauth2.Config{
		ClientID:    "1048782603835-6es9j7ehd7i1va12r79oupac7kg8r69f.apps.googleusercontent.com",
		ClientSecret: "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",
		RedirectURL:  "http://localhost:4000/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/contacts.readonly",
		},
		Endpoint:     google.Endpoint,
	}
	// Replace with your own Google client ID and secret
)