package main

import (
	"AuthServiceWeb3/pkg/handlers"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// CORS configuration
	r.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	})

	// Options handler to resolve our CORS issue jitter
	r.OPTIONS("/*any", func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.AbortWithStatus(http.StatusOK)
	})

	r.GET("/connect", handlers.HandleConnect)
	r.POST("/login", handlers.HandleLogin)
	r.POST("/register", handlers.HandleRegister)
	r.GET("/verify-email", handlers.HandleVerifyEmail)
	r.GET("/getUserBySessions", handlers.HandleGetUser)
	r.GET("/getWallets", handlers.CheckAuth, handlers.HandleGetWallets)
	r.GET("/getRecovery", handlers.CheckAuth, handlers.HandleGetRecovery)
	r.GET("/getUser", handlers.CheckAuth, handlers.HandleGetUser)
	r.POST("/forgot-password", handlers.HandleForgotPassword)
	r.POST("/recover-password", handlers.HandleRecoverPassword)
	r.POST("/createWalletEVM", handlers.CheckAuth, handlers.HandleCreateWalletEVM)
	r.POST("/createWalletSolana", handlers.CheckAuth, handlers.HandleCreateWalletSolana)
	r.GET("/createUserSecret", handlers.CreateUserSecret)
	r.GET("/getWalletFromSecret", handlers.GetWalletFromSecret)

	r.Run(":80")
}
