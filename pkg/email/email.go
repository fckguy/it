package email

import (
	"AuthServiceWeb3/pkg/models"
	"fmt"
	"net/smtp"
)

var smtpServer string = "smtp.gmail.com"
var username string = "contact@5thweb.io"
var password string = "J33tN1ggaz4l1f3"
var smtpPort string = "587"

func SendVerificationEmail(user models.User, token string) {
	from := username

	url := "http://webauth.5thweb.io/verify-email?token=" + token

	to := []string{
		user.Email,
	}

	subject := "Subject: Confirm your Infinity Auth Account!\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := `<html><body><h1><a href="` + url + `">Click this to confirm your account.</a></h1></body></html>`

	smtpHost := smtpServer

	message := []byte(subject + mime + body)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func SendShareToUser(email string, share string, address string) error {
	from := username;
	to := []string{
		email,
	}

	subject := "Subject: Your Infinity Web Wallet Secret Share\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := `<html><body><h1>Your secret share for wallet with address` + address + `is :` + share + `</h1></body></html>`

	smtpHost := smtpServer

	message := []byte(subject + mime + body)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		return err
	}

	return nil
}

func SendPasswordRecoveryToUser(email string, tokenString string) error {
	from := username;

	to := []string{
		email,
	}

	subject := "Subject: Recover your password.\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := `<html><body><h1>Click <a href="https://infinityauth.netlify.app/recover-password?key=`+tokenString +`">here</a> to recover your password.</h1></body></html>`

	smtpHost := smtpServer

	message := []byte(subject + mime + body)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		return err
	}

	return nil
}
