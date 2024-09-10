package repository

import (
	"context"
	"database/sql"
	"log"

	"github.com/google/uuid"
	"github.com/snipep/Profile_Managment_Application/pkg/Oauth"
	"github.com/snipep/Profile_Managment_Application/pkg/models"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

func GetAllUsers(db *sql.DB,) ([]models.User, error) {
	users := []models.User{}

	query := "SELECT is, email, passsword, name, category, dob, bio, avatar FROM users"
	rows, err := db.Query(query)
	if err != nil{
		return nil, err
	}

	defer rows.Close()
	for rows.Next(){
		var user models.User

		if err := rows.Scan(&user.Id, &user.Email, &user.Password, &user.Name, &user.Category, &user, &user.DOB, &user.Bio, &user.Avatar); err != nil{
			return nil, err
		}
		users = append(users, user)
	}
	if err = rows.Err();err != nil{
		return nil, err
	}

	return users, nil
}

func GetUserById(db *sql.DB, id string) (models.User, error) {
	var user models.User

	err := db.QueryRow("SELECT id, email, password, name, category, dob, bio, avatar FROM users WHERE id = ?", id).Scan(&user.Id, &user.Email, &user.Password, &user.Name, &user.Category, &user.DOB, &user.Bio, &user.Avatar)
	if err != nil{
		return user, err
	}

	// Format the date using a friendly format, e.g: "Jan 2, 2006"
	user.DOBFormatted = user.DOB.Format("2006-01-02")

	return user, nil
	
}

func GetUserByEmail(db *sql.DB, email string) (models.User, error) {
	var user models.User

	err := db.QueryRow("SELECT id, email, password, name, category, dob, bio, avatar FROM users WHERE email = ?", email).Scan(&user.Id, &user.Email, &user.Password, &user.Name, &user.Category, &user.DOB, &user.Bio, &user.Avatar)
	if err != nil{
		return user, err
	}

	return user, nil	
}

func CreateUser( db *sql.DB, user models.User) error {
	id, err := uuid.NewUUID()
	if err != nil{
		return err
	}

	// Convert id to string and set it on the user 
	user.Id = id.String()
	stmt, err := db.Prepare("INSERT INTO users (id, email, password, name, category, DOB, Bio, Avatar) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil{
		return err
	}
	defer stmt.Close()	

	_, err = stmt.Exec(user.Id, user.Email, user.Password, user.Name, user.Category, user.DOB, user.Bio, user.Avatar)

	if err != nil{
		return err
	}
	return nil
}

func UpdateUser(db *sql.DB, id string, user models.User) error {
	_, err := db.Exec("UPDATE users SET name = ?, category = ?, dob = ?, bio = ? WHERE id =?", user.Name, user.Category, user.DOB, user.Bio, user.Id)

	return err
}

func UpdateUserAvatar(db *sql.DB, userID string, filePath string) error {
	_, err := db.Exec("UPDATE users SET avatar = ? WHERE id = ?", filePath, userID)
	return err
}

func DeleteUser(db *sql.DB, id string) error {
	_, err := db.Exec("DELETE FROM users WHERE is = ? ", id)
	
	return err
}

func CreateGoogleUser( db *sql.DB, user models.User) error {
	id, err := uuid.NewUUID()
	if err != nil{
		return err
	}

	// Convert id to string and set it on the user 
	user.Id = id.String()

	// Hash the password 
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil{
		log.Fatal(err)
	}
	// Convert password to string and set it on the user 
	user.Password = string(hashedPassword)

	stmt, err := db.Prepare("INSERT INTO users (id, email, password, name, category, DOB, Bio, Avatar) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil{
		return err
	}
	defer stmt.Close()	

	_, err = stmt.Exec(user.Id, user.Email, user.Password, user.Name, user.Category, user.DOB, user.Bio, user.Avatar)

	if err != nil{
		return err
	}
	return nil
}

func refreshAccessToken(token *oauth2.Token) (*oauth2.Token, error) {
    tokenSource := Oauth.Oauth2Config.TokenSource(context.Background(), token)
    newToken, err := tokenSource.Token()
    if err != nil {
        return nil, err
    }
    return newToken, nil
}
