package auth

import (
	"AuthServiceWeb3/pkg/database"
	"AuthServiceWeb3/pkg/models"
	"errors"
	"fmt"
	"net/mail"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateRegisterJwt(user models.User) string {
	// TODO: Generate JWT
	secret := "RMGF2xHcjI07fhvelNKP"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(),
		"func":  "registerUser",
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		panic(err)
	}
	return tokenString
}

func VerifyRegisterJwt(token string) (models.User, error) {
	secret := "RMGF2xHcjI07fhvelNKP"
	claims := jwt.MapClaims{}

	_, err := jwt.ParseWithClaims(token, claims, func(tokenInfo *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		fmt.Println("1")
		fmt.Println(err)
		return models.User{}, errors.New(`Token not valid. This means that either you landed on this page by accident
		or the link has expired.`)
	} else if claims["exp"].(float64)-float64(time.Now().Unix()) < 0 {
		fmt.Println("2")
		fmt.Println("too old")
		return models.User{}, errors.New(`Token not valid. This means that either you landed on this page by accident
		or the link has expired.`)
	} else {
		user, err := database.GetUser(claims["email"].(string))
		if err != nil {
			fmt.Println("3")
			fmt.Println("Cant find user")
			fmt.Println("email: " + claims["email"].(string))
			return models.User{}, errors.New(`Token not valid. This means that either you landed on this page by accident
			or the link has expired.`)
		} else {
			return user, nil
		}
	}
}

func CreateForgotPassword(email string) string {
	// TODO: Generate JWT
	secret := "RMGF2xHcjI07fhvelNKP"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    email,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"function": "forgotPassword",
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		panic(err)
	}
	return tokenString
}

func VerifyForgotPassword(tokenString string, email string) (models.User, error) {
	secret := "RMGF2xHcjI07fhvelNKP"
	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return models.User{}, errors.New("Token not valid. This means that either you landed on this page by accident or the link has expired.")
	}

	if !token.Valid {
		return models.User{}, errors.New("Invalid session cookie")
	} else if claims["exp"].(float64)-float64(time.Now().Unix()) < 0 {
		return models.User{}, errors.New(`Token not valid. This means that either you landed on this page by accident
		or the link has expired.`)
	} else if claims["function"].(string) != "forgotPassword" {
		return models.User{}, errors.New(`Token not valid. This means that either you landed on this page by accident
		or the link has expired.`)
	} else if claims["email"].(string) != email {
		return models.User{}, errors.New(`Token not valid. This means that either you landed on this page by accident
		or the link has expired.`)
	} else {
		user, err := database.GetUser(claims["email"].(string))
		if err != nil {
			return models.User{}, errors.New(`Token not valid. This means that either you landed on this page by accident
			or the link has expired.`)
		} else {
			return user, nil
		}
	}
}

func CreateSessionCookie(userID string) string {
	sessionID, err := database.CreateNewSession(userID)
	if err != nil {
		panic(err)
	}

	secret := "RMGF2xHcjI07fhvelNKP"
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sessionID": sessionID,
		"exp":       int(now.AddDate(0, 0, 7).Unix()),
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		panic(err)
	}
	return tokenString
}

func VerifySessionCookie(tokenString string) (jwt.MapClaims, error) {
	secret := "RMGF2xHcjI07fhvelNKP"
	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, errors.New("Invalid session cookie")
	}

	if !token.Valid {
		return nil, errors.New("Invalid session cookie")
	}

	return claims, nil
}

func GetUserFromCookie(session string) (models.User, error) {
	claims, err := VerifySessionCookie(session)
	if err != nil {
		return models.User{}, errors.New("Invalid session.")
	}

	userID, err := database.GetUserIDFromSession(claims["sessionID"].(string))
	if err != nil {
		return models.User{}, errors.New("Invalid session.")
	}

	user, err := database.GetUserByID(userID)
	if err != nil {
		return models.User{}, errors.New("Invalid session.")
	}

	return user, nil
}

func GetUserFromCookieSafe(session string) (models.User, error) {
	claims, err := VerifySessionCookie(session)
	if err != nil {
		return models.User{}, errors.New("Invalid session.")
	}

	userID, err := database.GetUserIDFromSession(claims["sessionID"].(string))
	if err != nil {
		return models.User{}, errors.New("Invalid session.")
	}

	user, err := database.GetUserByIDSafe(userID)
	if err != nil {
		return models.User{}, errors.New("Invalid session.")
	}

	return user, nil
}

func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func CreateUserWalletSecret(userID string, walletID string) (string, error) {
	err := database.VerifyUserWallet(userID, walletID)
	if err != nil {
		return "", err
	}
	secret := "RMGF2xHcjI07fhvelNKP"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":   userID,
		"walletID": walletID,
		"exp":      time.Now().Add(time.Minute * 5).Unix(),
		"func":     "createUserWalletSecret",
	})

	tokenString, err := token.SignedString([]byte(secret))

	return tokenString, nil
}

func DecryptUserWalletSecret(tokenString string) (string, error) {
	claims := jwt.MapClaims{}
	secret := "RMGF2xHcjI07fhvelNKP"
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", errors.New("Invalid token.")
	} else if claims["exp"].(float64)-float64(time.Now().Unix()) < 0 {
		return "", errors.New(`Token expired.`)
	} else if claims["function"].(string) != "createUserWalletSecret" {
		return "", errors.New(`Token not valid. This means that either you landed on this page by accident
		or the link has expired.`)
	} else {
		return claims["walletID"].(string), nil
	}
}
