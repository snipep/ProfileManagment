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
	Id string
	Email string
	Name string
	GivenName string
	FamilyName string
	Avatar string
}