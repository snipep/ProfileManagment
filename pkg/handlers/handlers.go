package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/snipep/Profile_Managment_Application/pkg/models"
	"github.com/snipep/Profile_Managment_Application/pkg/repository"
	"golang.org/x/crypto/bcrypt"
)
var Oauthstring = "qwertyuio"

func RegisterPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func (w http.ResponseWriter, r *http.Request)  {
		tmpl.ExecuteTemplate(w, "register", nil)
	}
}	

func Registrationhandler(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		var user models.User

		var errorMessage []string
		
		// Parse the form data
		r.ParseForm()
 
		user.Name = r.FormValue("name")
		user.Email = r.FormValue("email")
		user.Password = r.FormValue("password")
		user.Category, _ = strconv.Atoi(r.FormValue("category"))

		// Name Validation 
		if user.Name == ""{
			errorMessage = append(errorMessage, "Name is required")
		}
		// Email Validation 
		if user.Email == ""{
			errorMessage = append(errorMessage, "Email is required")
		}
		// Password Validation 
		if user.Password == ""{
			errorMessage = append(errorMessage, "Password is required")
		}
		if len(errorMessage) > 0{
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return
		}

		// Hash the password 
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil{
			errorMessage = append(errorMessage, "Failed to hash password")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return 
		}

		user.Password  = string(hashedPassword)

		// Set default values 
		user.DOB = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		user.Bio = "Bio goes here"
		user.Avatar = ""

		// Create user in the database 
		err = repository.CreateUser(db, user)
		if err != nil{
			errorMessage = append(errorMessage, "Failed to create user: "+ err.Error())
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return 
		}

		// Set HTTP status code to 204 (not content) and set 'HX-Location' header to signal to redirect 
		w.Header().Set("HX-Location", "/login")
		w.WriteHeader(http.StatusNoContent)
	}
}	

func LoginPage(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "login", nil)
	}
}

func LoginHandler(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		r.ParseForm()
		email := r.FormValue("email")
		password := r.FormValue("password")

		var errorMessage []string
		// Email Validation 
		if email == ""{
			errorMessage = append(errorMessage, "Email is required")
		}
		// Password Validation 
		if password == ""{
			errorMessage = append(errorMessage, "Password is required")
		}
		if len(errorMessage) > 0{
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return
		}
		
		// Retrieve user by email 
		user, err := repository.GetUserByEmail(db, email)
		if err != nil{
			if err == sql.ErrNoRows{
				errorMessage = append(errorMessage, "Invalid email or password")
				tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
				return 
			}

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return 
		}

		// Compare the hashed password from the DB with the provider password 
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil{
			errorMessage = append(errorMessage, "Invalid email or password")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return 
		}

		// Create session and authenticate the user 
		session, err := store.Get(r, "logged-in-user")
		if err != nil{
			http.Error(w, "Server error", http.StatusInternalServerError)
			return 
		}
		session.Values["user_id"] = user.Id
		if err := session.Save(r, w);err != nil{
			http.Error(w, "Error saving session", http.StatusInternalServerError)
			return 
		}

		// Set HX-Location header and return 204 No Content status 
		w.Header().Set("HX-Location", "/")
		w.WriteHeader(http.StatusNoContent)

	}
}

func CheckLoggedIn(w http.ResponseWriter, r *http.Request, store *sessions.CookieStore, db *sql.DB) (models.User, string) {
	session, err := store.Get(r, "logged-in-user")
	if err != nil{
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return models.User{}, ""
	}

	// Check if the user_id is present in the session 
	userID, ok := session.Values["user_id"]
	if !ok{
		fmt.Println("Redirecting to /login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)  //303 required for the redirect to happen

		return models.User{}, ""
	}

	// Fetch user details from the database 
	user, err := repository.GetUserById(db, userID.(string))
	if err != nil{
		if err == sql.ErrNoRows{
			// No user found, possibly hanfle by clearing the session or redirecting to login 
			session.Options.MaxAge = -1 	//Clear the session
			session.Save(r, w)

			fmt.Println("Redirecting to /login")
			http.Redirect(w, r, "/login", http.StatusSeeOther)

			return models.User{}, ""
		}

		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return models.User{}, ""
	}
	return user, userID.(string)
}

func HomePage(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		user, _ := CheckLoggedIn(w, r, store, db)

		// User is logged in and found, render the homepage with user data 
		if err := tmpl.ExecuteTemplate(w, "home.html", user);err != nil{
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func EditPage(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		user, _ := CheckLoggedIn(w, r, store, db)
		if err := tmpl.ExecuteTemplate(w, "editProfile", user); err != nil{
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func UpdateProfileHandler(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		// Retrieve the session 
		currentUserProfile, userID := CheckLoggedIn(w, r, store, db)

		// Parse the form 
		if err := r.ParseForm();err != nil{
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return 
		}
		 
		var errorMessage []string

		name := r.FormValue("name")
		bio := r.FormValue("bio")
		dobStr := r.FormValue("dob")

		// Name Validation 
		if name == ""{ 
			errorMessage = append(errorMessage, "Name is required")
		}
		// DOB Validation 
		if dobStr == ""{
			errorMessage = append(errorMessage, "Date of birth is required")
		}
		dob, err := time.Parse("2006-01-02", dobStr)
		if err != nil{
			errorMessage = append(errorMessage, "Invalid date format")
		}
		//Handle validation error
		if len(errorMessage) > 0{
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return
		}

		//Create user struct
		user := models.User{
			Id: userID,
			Name: name,
			DOB: dob,
			Bio: bio,
			Category: currentUserProfile.Category,
		}

		// Call the repository function to update the user 
		if err := repository.UpdateUser(db, userID, user);err != nil{
			errorMessage = append(errorMessage, "Failed to update user")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			log.Fatal(err)
			return 
		}

		// Redirect or return success 
		// Set HX-Locaion header and return 204 No Content status 
		w.Header().Set("HX-Location", "/")
		w.WriteHeader(http.StatusNoContent) 
	}
}

func AvatarPage(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		user, _ := CheckLoggedIn(w, r, store, db)

		if err := tmpl.ExecuteTemplate(w, "uploadAvatar", user);err != nil{
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func UploadAvatarHandler(db *sql.DB, tmpl *template.Template, store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		user, userID := CheckLoggedIn(w, r, store, db)

		// Initialize error message slice 
		var errorMessage []string

		// Parse the multipart form, 10MB max upload size 
		r.ParseMultipartForm(10 << 20)

		// Retrieve the file from form data 
		file, handler, err := r.FormFile("avatar")
		if err != nil{
			if err == http.ErrMissingFile{
				errorMessage = append(errorMessage, "No file submitted")
			} else{
				errorMessage = append(errorMessage, "Error retrieving the file")
			}

			if len(errorMessage) > 0{
				tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
				return 
			}
		}
		defer file.Close()

		// Generate a unique filename to prevent overwriting and conflicts 
		uuid, err := uuid.NewRandom()
		if err != nil{
			errorMessage = append(errorMessage, "Error generating unique identifier")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return 
		}
		filename := uuid.String() + filepath.Ext(handler.Filename) //Append file extension

		// Create the full path for saving the file 
		filePath := filepath.Join("uploads", filename)

		// Save the file to the server
		dst, err := os.Create(filePath)
		if err != nil{
			errorMessage = append(errorMessage, "Error saving the file")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return 
		}
		defer dst.Close()
		if _, err = io.Copy(dst, file);err != nil{
			errorMessage = append(errorMessage, "Error saving the file")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			return
		}

		// Update the user's avatar in the database 
		if err := repository.UpdateUserAvatar(db, userID, filename);err != nil{
			errorMessage = append(errorMessage, "Error updating the avatar")
			tmpl.ExecuteTemplate(w, "autherrors", errorMessage)
			log.Fatal(err)
			return 
		}

		// Delete current image from the intial fetch  of theuser 
		if user.Avatar != ""{
			oldAvatarPath := filepath.Join("uploads", user.Avatar)

			// Chech if the oldPath is not the same as the new path 
			if oldAvatarPath != filePath{
				if err := os.Remove(oldAvatarPath);err != nil{
					fmt.Printf("Warning: failed to delete old avatar file: %s\n", err)
				}
			}
		}

		// Navigatin to the profile page after the update 
		w.Header().Set("HX-Location", "/")
		w.WriteHeader(http.StatusNoContent)

	}
}

func LogoutHandler(store *sessions.CookieStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "logged-in-user")
		if err != nil{
			http.Error(w, "internL Server Error", http.StatusInternalServerError)
			return 
		}

		// Remove the user from the session 
		delete(session.Values, "user_id")

		// Save the changes to the session 
		if err = session.Save(r, w);err != nil{
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return 
		}

		// Clear the session coockie 
		session.Options.MaxAge = -1
		session.Save(r, w)

		// Redirect to login page 
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}
