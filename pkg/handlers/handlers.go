package handlers

import (
	"AuthServiceWeb3/pkg/auth"
	"AuthServiceWeb3/pkg/database"
	"AuthServiceWeb3/pkg/email"
	"AuthServiceWeb3/pkg/models"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/vault/shamir"
	"github.com/portto/solana-go-sdk/types"
)

func HandleRegister(c *gin.Context) {
	var userLogin models.UserLogin
	err := c.Bind(&userLogin)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"One or more params are wrong"}})
		return
	}

	if !auth.IsValidEmail(userLogin.Email) {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid email address."}})
		return
	}

	user := models.User{Email: userLogin.Email, Password: database.HashPassword(userLogin.Password), EmailVerified: false}

	err = database.CreateUser(user)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"User already exists."}})
		return
	}

	// Verify blockchain signatures

	token := auth.GenerateRegisterJwt(user)
	email.SendVerificationEmail(user, token)

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
	})
}

func HandleVerifyEmail(c *gin.Context) {
	token, ok := c.GetQuery("token")
	if !ok {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"No token specified."}})
		return
	}

	user, err := auth.VerifyRegisterJwt(token)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{err.Error()}})
		return
	} else {
		err := database.VerifyUser(user)
		if err != nil {
			SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Something went wrong."}})
			return
		} else {
			c.JSON(http.StatusOK, gin.H{
				"status": "Succesfully verified email.",
			})
		}
	}
}

func HandleLogin(c *gin.Context) {
	var userLogin models.UserLogin
	err := c.Bind(&userLogin)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"One or more params are wrong"}})
		return
	}

	user, err := database.GetUser(userLogin.Email)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials"}})
		return
	} else if !user.EmailVerified {
		fmt.Println("not verified")
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Please confirm your email before logging in."}})
		return
	} else if !database.CheckPasswordHash(userLogin.Password, user.Password) {
		fmt.Println("not valid password")
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials"}})
		return
	} else {
		now := time.Now()
		cookie := auth.CreateSessionCookie(user.UserID)
		// Get the current host URL JITTTTTEERRR
		host := c.Request.Host
		c.SetSameSite(http.SameSiteNoneMode)
		c.SetCookie("session", cookie, int(now.AddDate(0, 0, 7).Unix()), "/", host, true, true)
		c.Set("userID", user.UserID) // Set userID in context for later use
		c.IndentedJSON(http.StatusOK, gin.H{"status": "Succesfully logged in."})
		return
	}

}

func handleSessionLogin(c *gin.Context) {
	sessionCookie, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "Session cookie is missing"})
		return
	}
	claims, err := auth.VerifySessionCookie(sessionCookie)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "Session cookie is invalid"})
		return
	}

	sessionID := claims["sessionID"].(string)
	userID, err := database.GetUserIDFromSession(sessionID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "Invalid session userID"})
		return
	}
	c.Set("userID", userID) // Set userID in context for later use
	c.IndentedJSON(http.StatusOK, gin.H{"status": "Successfully logged in", "userID": userID})
}

func HandleCreateWalletEVM(c *gin.Context) {
	sessionCookie, err := c.Cookie("session")
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials or not logged in.."}})
		return
	}
	user, err := auth.GetUserFromCookieSafe(sessionCookie)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials or not logged in.."}})
		return
	}

	userID := user.UserID

	// Generate a new private key
	privateKey, err := generateWalletSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
		return
	}

	privateKeyString := hexutil.Encode(privateKey)

	// Convert the privateKey to ecdsa.PrivateKey
	privateKeyECDSA, err := crypto.ToECDSA(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to convert private key"})
		return
	}

	// Generate an Ethereum wallet address from the private key
	walletAddress := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey).Hex()

	shares, err := splitSecret([]byte(privateKeyString)) // split the secret into 3 shares

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to split secret"})
		return
	}

	password := generatePassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
		return
	}

	encryptedSecret := database.EncryptKey([]byte(password), privateKeyString)

	err = database.SaveWallet(userID, walletAddress, true, hex.EncodeToString(shares[0]), encryptedSecret)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save shares"})
		return
	}

	user, err = database.GetUserByID(userID) // get the user's email
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	err = email.SendShareToUser(user.Email, password, walletAddress) // send the password for recovery share
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send share", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "wallet created", "walletAddress": walletAddress})
}

func HandleCreateWalletSolana(c *gin.Context) {
	sessionCookie, err := c.Cookie("session")
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials or not logged in.."}})
		return
	}
	user, err := auth.GetUserFromCookieSafe(sessionCookie)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials or not logged in.."}})
		return
	}

	userID := user.UserID

	// Generate a new Solana wallet
	wallet := types.NewAccount()

	// Get the public key as a string
	publicKey := wallet.PublicKey.ToBase58()

	// Get the private key as a byte array
	privateKey := wallet.PrivateKey

	privateKeyString, err := json.Marshal(privateKey)

	privateKeyStringg := base64.StdEncoding.EncodeToString(privateKeyString)

	// Split the secret into 3 shares
	shares, err := splitSecret([]byte(privateKeyStringg))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to split secret"})
		return
	}

	user, err = database.GetUserByID(userID) // get the user's email
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	password := generatePassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
		return
	}

	encryptedSecret := database.EncryptKey([]byte(password), privateKeyStringg)

	err = database.SaveWallet(userID, publicKey, false, hex.EncodeToString(shares[0]), encryptedSecret)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save wallet"})
		return
	}

	err = email.SendShareToUser(user.Email, password, publicKey) // send the password for recovery to user
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send share", "detail": err.Error()})
		return
	}
	//Notes [for later use on recovery]
	// types.AccountFromBase58 allows you to import a wallet with a base58-encoded private key. ** I think we would use this one **
	// types.AccountFromBytes allows you to import a wallet with a byte slice private key.
	// types.AccountFromHex allows you to import a wallet with a hex-encoded private key.

	c.JSON(http.StatusOK, gin.H{"status": "wallet created", "walletAddress": publicKey})
}

func HandleGetWallets(c *gin.Context) {
	// for later, we need to get logic for unique wallets and not shareable wallets and stuff

	// apiKey, ok1 := c.GetQuery("apiKey")
	// if !ok1 {
	// 	SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"One or more params wrong."}})
	// 	return
	// }

	sessionCookie, err := c.Cookie("session")
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid session."}})
		return
	}

	user, err := auth.GetUserFromCookie(sessionCookie)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid session."}})
		return
	}

	wallets, err := database.GetWalletsByUserID(user.UserID)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusInternalServerError, Error: []string{"Something went wrong"}})
		return
	}

	stringified, _ := json.MarshalIndent(wallets, "", "  ")
	c.Data(http.StatusOK, "application/json", stringified)
}

func HandleGetRecovery(c *gin.Context) {
	walletID, ok1 := c.GetQuery("walletID")
	if !ok1 {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"One or more params wrong."}})
		return
	}

	sessionCookie, err := c.Cookie("session")
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid session."}})
		return
	}

	user, err := auth.GetUserFromCookie(sessionCookie)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid session."}})
		return
	}

	wallet, err := database.GetRecoveryByWalletID(walletID, user.UserID)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"recovery": wallet.Recovery,
	})
}

func HandleGetUser(c *gin.Context) {
	sessionCookie, err := c.Cookie("session")
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials or not logged in.."}})
		return
	}
	user, err := auth.GetUserFromCookieSafe(sessionCookie)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials or not logged in.."}})
		return
	}

	stringified, _ := json.MarshalIndent(user, "", "  ")
	c.Data(http.StatusOK, "application/json", stringified)

}

func HandleForgotPassword(c *gin.Context) {
	var userPost models.PasswordRecovery
	err := c.Bind(&userPost)

	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid parameters."}})
		return
	}

	if !auth.IsValidEmail(userPost.Email) {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid email address."}})
		return
	}

	user, err := database.GetUser(userPost.Email)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"If you have an account, an email has been sent."}})
		return
	}

	tokenString := auth.CreateForgotPassword(user.Email)

	err = email.SendPasswordRecoveryToUser(user.Email, tokenString)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Something went wrong."}})
		return
	}
}

func HandleRecoverPassword(c *gin.Context) {
	var userPost models.AuthRecoverPassword
	err := c.Bind(&userPost)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid parameters."}})
		return
	}

	user, err := auth.VerifyForgotPassword(userPost.TokenString, userPost.Email)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{err.Error()}})
		return
	}

	err = database.UpdateRecoverPassword(user.Email, userPost.Password)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "Succesfully updated password!",
	})

}

func generateWalletSecret() ([]byte, error) {
	// Generate a new random private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	// Get the bytes of the private key
	privateKeyBytes := crypto.FromECDSA(privateKey)

	return privateKeyBytes, nil
}

func splitSecret(secret []byte) ([][]byte, error) {
	n := 3
	t := 2

	// Split the secret using Shamir's Secret Sharing scheme
	shares, err := shamir.Split(secret, n, t)
	if err != nil {
		return nil, err
	}
	return shares, nil
}

func SendResponse(c *gin.Context, response models.Response) {
	if len(response.Message) > 0 {
		c.JSON(response.Status, map[string]interface{}{"message": strings.Join(response.Message, "; ")})
	} else if len(response.Error) > 0 {
		c.JSON(response.Status, map[string]interface{}{"error": strings.Join(response.Error, "; ")})
	}
}

func CheckAuth(c *gin.Context) {
	sessionCookie, err := c.Cookie("session")
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials or not logged in. Please try again."}})
		c.Abort()
		return
	}
	claims, err := auth.VerifySessionCookie(sessionCookie)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid credentials or not logged in. Please try again."}})
		c.Abort()
		return
	}

	sessionID := claims["sessionID"].(string)
	_, err = database.GetUserIDFromSession(sessionID)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid session userID"}})
		c.Abort()
		return
	} else {
		c.Next()
	}
}

func HandleConnect(c *gin.Context) {
	apiKey, ok1 := c.GetQuery("apiKey")
	if !ok1 {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"One or more params wrong."}})
		return
	}

	_, err := database.GetPlatformByKey(apiKey)
	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"Invalid apiKey"}})
		return
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
		})
	}
}

func generatePassword() string {
	length := 32
	rand.Seed(time.Now().UnixNano())

	digits := "0123456789"
	specials := "~=+%^*/()[]{}/!@#$?|"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		digits + specials
	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = specials[rand.Intn(len(specials))]
	for i := 2; i < length; i++ {
		buf[i] = all[rand.Intn(len(all))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	str := string(buf) // E.g. "3i[g0|)z"
	return str
}

func CreateUserSecret(c *gin.Context) {
	userID, ok1 := c.GetQuery("userID")
	walletID, ok2 := c.GetQuery("walletID")
	if !ok1 {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"One or more params wrong."}})
		return
	}

	if !ok2 {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"One or more params wrong."}})
		return
	}

	tokenString, err := auth.CreateUserWalletSecret(userID, walletID)

	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func GetWalletFromSecret(c *gin.Context) {
	token, ok1 := c.GetQuery("token")

	if !ok1 {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{"One or more params wrong."}})
		return
	}

	walletID, err := auth.DecryptUserWalletSecret(token)

	if err != nil {
		SendResponse(c, models.Response{Status: http.StatusBadRequest, Error: []string{err.Error()}})
		return
	} else {
		c.JSON(http.StatusOK, gin.H{
			"walletID": walletID,
		})
	}
}
