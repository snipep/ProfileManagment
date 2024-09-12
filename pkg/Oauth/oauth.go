package Oauth

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/markbates/goth/providers/google"
	"golang.org/x/oauth2"
)

var Oauth2Config *oauth2.Config

func init() {
    // Load environment variables from .env file
    err := godotenv.Load()
    if err != nil {
        log.Fatalf("Error loading .env file")
    }
	fmt.Println("ClientID: ", os.Getenv("GOOGLE_CLIENT_ID"))
	fmt.Println("ClientSecret", os.Getenv("GOOGLE_CLIENT_SECRET"))

	// Initialize Oauth2Config after loading environment variables
	Oauth2Config = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:4000/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/user.birthday.read",
		},
		Endpoint:     google.Endpoint,
	}
}


