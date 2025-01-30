package main

import (
	"github.com/gin-gonic/gin"

	"auth_example"
)

func main() {
	r := gin.New()
	r.Use(gin.Recovery())
	app := auth_example.BuildApplication(r)
	app.RunUntilStopped()
}
