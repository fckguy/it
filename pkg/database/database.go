package database

import (
	"AuthServiceWeb3/pkg/models"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	_ "github.com/go-sql-driver/mysql"
	uuid "github.com/nu7hatch/gouuid"
	"golang.org/x/crypto/bcrypt"
)

func GetDB() *sql.DB {
	db, err := sql.Open("mysql", "root:mXA740W1O#6y@tcp(127.0.0.1:3306)/web3auth?parseTime=true")

	if err != nil {
		panic(err)
	}
	return db
}

func GetUser(email string) (models.User, error) {
	db := GetDB()
	rows, err := db.Query("SELECT * FROM users WHERE email = ?", email)
	defer db.Close()
	if err != nil {
		panic(err)
	}
	var user models.User
	for rows.Next() {
		err = rows.Scan(&user.Email, &user.UserID, &user.Password, &user.EmailVerified, &user.Added_date)
		if err != nil {
			panic(err)
		}
		break
	}

	if user.Email == "" {
		return user, errors.New("No user found")
	} else {
		return user, nil
	}
}

func GetUserByID(id string) (models.User, error) {
	db := GetDB()
	rows, err := db.Query("SELECT * FROM users WHERE userID = ?", id)
	defer rows.Close()
	defer db.Close()
	if err != nil {
		panic(err)
	}
	var user models.User
	for rows.Next() {
		err = rows.Scan(&user.Email, &user.UserID, &user.Password, &user.EmailVerified, &user.Added_date)
		if err != nil {
			panic(err)
		}
		break
	}

	if user.Email == "" {
		return user, errors.New("No user found")
	} else {
		return user, nil
	}
}

func GetUserByIDSafe(id string) (models.User, error) {
	db := GetDB()
	rows, err := db.Query("SELECT email, userID FROM users WHERE userID = ?", id)
	defer rows.Close()
	defer db.Close()
	if err != nil {
		panic(err)
	}
	var user models.User
	for rows.Next() {
		err = rows.Scan(&user.Email, &user.UserID)
		if err != nil {
			panic(err)
		}
		break
	}

	if user.Email == "" {
		return user, errors.New("No user found")
	} else {
		return user, nil
	}
}

func GetSession(sessionID string) (models.Session, error) {
	db := GetDB()
	rows, err := db.Query("SELECT * FROM sessions WHERE sessionID = ?", sessionID)
	defer rows.Close()
	defer db.Close()
	if err != nil {
		panic(err)
	}
	var session models.Session
	for rows.Next() {
		err = rows.Scan(&session.SessionID, &session.UserID)
		if err != nil {
			panic(err)
		}
		break
	}

	if session.SessionID == "" {
		return session, errors.New("No session found")
	} else {
		return session, nil
	}
}

func CreateUser(user models.User) error {
	db := GetDB()
	u4, err := uuid.NewV4()
	defer db.Close()
	if err != nil {
		panic(err)
	}
	insert, err := db.Query("INSERT INTO users (email, userID, password, emailVerified) values (?,?,?,?)", user.Email, u4.String(), user.Password, user.EmailVerified)
	if err != nil {
		defer insert.Close()
		fmt.Println(err)
		fmt.Println(u4.String())
		return errors.New("User already exists.")
	} else {
		defer insert.Close()
		return nil
	}
}

func VerifyUser(user models.User) error {
	db := GetDB()
	defer db.Close()
	update, err := db.Query("UPDATE users SET emailVerified = true WHERE email = ?", user.Email)
	defer update.Close()
	if err != nil {
		return errors.New("Something went wrong.")
	} else {
		defer update.Close()
		return nil
	}

}

func HashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CreateNewSession(userID string) (string, error) {
	db := GetDB()
	u4, err := uuid.NewV4()
	defer db.Close()
	if err != nil {
		panic(err)
	}
	insert, err := db.Query("INSERT INTO sessions (sessionID, userID) values (?,?)", u4.String(), userID)
	if err != nil {
		defer insert.Close()
		return "", errors.New("Something went wrong.")
	} else {
		defer insert.Close()
		return u4.String(), nil
	}
}

func GetUserIDFromSession(sessionID string) (string, error) {
	session, err := GetSession(sessionID)
	if err != nil {
		return "", err
	}
	return session.UserID, nil
}

func SaveWallet(userID string, walletAddress string, isEVM bool, secret string, recovery string) error {
	db := GetDB()
	defer db.Close()

	u4, err := uuid.NewV4()

	_, err = db.Exec("INSERT INTO wallets (userID, walletID, address, isEVM, secret, recovery) VALUES (?,?,?,?,?,?)",
		userID, u4.String(), walletAddress, isEVM, secret, recovery)
	if err != nil {
		panic(err)
		return err
	}

	return nil
}

func GetWalletsByUserID(userID string) ([]models.Wallet, error) {
	db := GetDB()
	rows, err := db.Query("SELECT walletID, address, isEVM, secret, added_date FROM wallets WHERE userID = ?", userID)
	defer db.Close()
	defer rows.Close()
	if err != nil {
		return []models.Wallet{}, errors.New("Something went wrong.")
	}
	var wallets []models.Wallet
	for rows.Next() {
		var wallet models.Wallet
		err = rows.Scan(&wallet.WalletID, &wallet.Address, &wallet.IsEVM, &wallet.Secret, &wallet.Added_date)
		if err != nil {
			return []models.Wallet{}, errors.New("Something went wrong.")
		}
		wallets = append(wallets, wallet)
	}

	return wallets, nil
}

func GetRecoveryByWalletID(walletID string, userID string) (models.Wallet, error) {
	db := GetDB()
	rows, err := db.Query("SELECT * FROM wallets WHERE walletID = ? AND userID = ?", walletID, userID)
	defer rows.Close()
	defer db.Close()
	if err != nil {
		panic(err)
		return models.Wallet{}, errors.New("Something went wrong.")
	}
	var wallet models.Wallet
	for rows.Next() {
		err = rows.Scan(&wallet.UserID, &wallet.WalletID, &wallet.PlatformID, &wallet.IsPlatformLocked, &wallet.Address, &wallet.IsEVM, &wallet.Secret, &wallet.Recovery, &wallet.Added_date)
		if err != nil {
			return models.Wallet{}, errors.New("Something went wrong.")
		}
		break
	}

	if wallet.WalletID == "" {
		return models.Wallet{}, errors.New("Wallet not found.")
	}
	return wallet, nil
}

func GetPlatformByKey(apiKey string) (models.Client, error) {
	db := GetDB()
	rows, err := db.Query("SELECT * FROM wallets WHERE apiKey = ?", apiKey)
	defer rows.Close()
	defer db.Close()

	if err != nil {
		return models.Client{}, errors.New("Something went wrong.")
	}
	var client models.Client
	for rows.Next() {
		err = rows.Scan(&client.APIKey, &client.PlatformID, &client.UseUniqueWallet, &client.UseSingleWallet, &client.StartDate, &client.EndDate)
		if err != nil {
			return models.Client{}, errors.New("Something went wrong.")
		}
		break
	}

	if client.PlatformID == "" {
		return models.Client{}, errors.New("Platform not found.")
	}
	return client, nil
}

func UpdateRecoverPassword(email string, password string) error {
	password = HashPassword(password)

	db := GetDB()
	defer db.Close()
	update, err := db.Query("UPDATE users SET password = ? WHERE email = ?", password, email)
	defer update.Close()
	if err != nil {
		defer update.Close()
		return errors.New("Something went wrong.")
	} else {
		defer update.Close()
		return nil
	}
}

func EncryptKey(key []byte, plaintext string) string {
	aesCypher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(aesCypher)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}
	encrypted := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(encrypted)
}

func VerifyUserWallet(userID string, walletID string) error {
	db := GetDB()
	rows, err := db.Query("SELECT walletID, address, isEVM, secret, added_date FROM wallets WHERE userID = ? AND walletID = ?", userID, walletID)
	defer db.Close()
	defer rows.Close()
	if err != nil {
		return errors.New("Something went wrong.")
	}
	var wallets []models.Wallet
	for rows.Next() {
		var wallet models.Wallet
		err = rows.Scan(&wallet.WalletID, &wallet.Address, &wallet.IsEVM, &wallet.Secret, &wallet.Added_date)
		if err != nil {
			return errors.New("Something went wrong.")
		}
		wallets = append(wallets, wallet)
	}

	if len(wallets) == 0 {
		return errors.New("No wallet found.")
	}

	return nil
}
