package models

import (
	"time"
)

type User struct {
	Email         		string		`json:"email"`
	UserID				string		`json:"userID"`
	EmailVerified 		bool		`json:"emailVerified"`
	Password			string		`json:"password"`
	Added_date			time.Time	`json:"added_date"`
}

type Session struct {
	SessionID		string	`json:"sessionID"`
	UserID			string	`json:"userID"`
}

type Client struct {
	APIKey     			string		`json:"apiKey"`
	PlatformID     		string		`json:"platformID"`
	UseUniqueWallet 	bool		`json:"UseUniqueWallet"`
	UseSingleWallet		bool		`json:"UseSingleWallet"`
	StartDate			time.Time	`json:"startDate"`
	EndDate				time.Time	`json:"endDate"`
}

type UserLogin struct {
	Email string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Wallet struct {
	UserID				string		`json:"userID"`
	WalletID			string		`json:"walletID"`
	PlatformID			string		`json:"platformID"`
	IsPlatformLocked 	bool		`json:"isPlatformLocked"`
	Address				string		`json:"address"`
	IsEVM				bool		`json:"isEVM"`
	Secret				string		`json:"secret"`
	Recovery			string		`json:"recovery"`
	Added_date			time.Time	`json:"added_date"`
}

type PasswordRecovery struct {
	Email			string		`json:"email" binding:"required"`
}

type AuthRecoverPassword struct {
	Email			string		`json:"email" binding:"required"`
	TokenString		string		`json:"tokenString" binding:"required"`
	Password		string		`json:"password" binding:"required"`
}

type Response struct {
	Status  int
	Message []string
	Error   []string
}