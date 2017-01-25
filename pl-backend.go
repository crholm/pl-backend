package main

import (
	"github.com/labstack/echo"
	"strconv"
	"github.com/crholm/pl-backend/resources"
	"github.com/crholm/pl-backend/config"
	"os"
)



func main() {

	config.LoadConfig(os.Args[1]);


	e := echo.New()

	// API doc, static page and browser version?
	e.GET("/", resources.Noop)


	// SETUP
	// Create repository and Send OTP to link device
	e.POST("/:email", resources.InitDeviceLinking)

	// Link account with OTP and return Valut key
	e.POST("/:email/link", resources.FinishDeviceLinking)


	// WORKING AND SAVING
	// Get latest vault
	e.GET("/vaults/:token", resources.Noop)

	// Get save vault
	e.POST("/vaults/:token", resources.Noop)

	// List all revisions
	e.GET("/vaults/:token/revisions", resources.Noop)

	// Get specific revision
	e.GET("/vaults/:token/revisions/:revision", resources.Noop)


	// PROF OF WORK STUFF
	// Get proof of work puzzle
	e.GET("/pow",  resources.GetPow)

	// Exchange proof of work puzzle to do action
	e.POST("/pow", resources.ExchangePow)



	address := config.Get().Server.Interface + ":" + strconv.Itoa(config.Get().Server.Port)

	e.Logger.Fatal(e.Start(address))
}