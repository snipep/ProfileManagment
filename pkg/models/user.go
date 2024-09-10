package models

import "time"

type User struct {
	Id       string
	Email    string
	Password string
	Name     string
	Category int
	DOB      time.Time
	DOBFormatted string
	Bio string
	Avatar string
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}
	
type Token struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`
    Expiry       time.Time `json:"expiry"`
}
