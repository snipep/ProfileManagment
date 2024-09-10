package Oauth


import (
	"github.com/markbates/goth/providers/google"
	"golang.org/x/oauth2"
)


var (
	Oauth2Config = &oauth2.Config{
		ClientID:    "532842498854-np7198145viidpmq454vn6g4q7of6mg0.apps.googleusercontent.com",
		ClientSecret: "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",
		RedirectURL:  "http://localhost:4000/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/user.birthday.read",
		},
		Endpoint:     google.Endpoint,
	}
)