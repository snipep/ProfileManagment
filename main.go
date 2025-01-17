package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"text/template"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/snipep/Profile_Managment_Application/pkg/handlers"
)

var (
	Store = sessions.NewCookieStore([]byte("usermanagmentsecret"))
	db *sql.DB
	tmpl *template.Template
)

func init()  {
	tmpl, _ = template.ParseGlob("templates/*.html")	

	// Setting up session 
	Store.Options = &sessions.Options{
		Path: "/",
		MaxAge: 3600 *3,
		HttpOnly: true,
	}
}

func initDB()  {
	var err error

	db, err = sql.Open("mysql", "root:root@tcp(127.0.0.1:3333)/usermanagment?parseTime=true")
	if err != nil{
		log.Fatal(err)
	}

	if err = db.Ping();err != nil{
		log.Fatal(err)
	}
	fmt.Println("-----MySQL Connection Established-----")
}

func main()  {
	grouter := mux.NewRouter()
	
	//Setup MySQL
	initDB()
	defer db.Close()

	// File Server 
	fileServer := http.FileServer(http.Dir("./uploads"))
	grouter.PathPrefix("/uploads/").Handler(http.StripPrefix("/uploads", fileServer))

	//All dynamic routes
	// handle Home page 
	grouter.HandleFunc("/", handlers.HomePage(db, tmpl, Store)).Methods("GET")
	// Handle regirstation page 
	grouter.HandleFunc("/register", handlers.RegisterPage(db, tmpl)).Methods("GET")
	// Handles the registration 
	grouter.HandleFunc("/register", handlers.Registrationhandler(db, tmpl)).Methods("POST")
	// Handle Login Page 
	grouter.HandleFunc("/login", handlers.LoginPage(db, tmpl)).Methods("GET")
	//Handle Login Process
	grouter.HandleFunc("/login", handlers.LoginHandler(db, tmpl, Store)).Methods("POST")
	//Handle the Edit Page
	grouter.HandleFunc("/edit", handlers.EditPage(db, tmpl, Store)).Methods("GET")
	//Handle the edit process
	grouter.HandleFunc("/edit", handlers.UpdateProfileHandler(db, tmpl, Store)).Methods("POST") 
	// Handle the Avatar Page 
	grouter.HandleFunc("/upload-avatar", handlers.AvatarPage(db, tmpl, Store)).Methods("GET")
	// Handle the uploading of Avatar
	grouter.HandleFunc("/upload-avatar", handlers.UploadAvatarHandler(db, tmpl, Store)).Methods("POST")
	// Handle logout page 
	grouter.HandleFunc("/logout", handlers.LogoutHandler(Store)).Methods("GET")

	
	fmt.Println("----Server is running on PORT:4000----")
	http.ListenAndServe(":4000", grouter)
}
