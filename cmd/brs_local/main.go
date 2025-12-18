package main

import (
	"brs/internal/db"
	"brs/internal/server"
	"log"
	"os"

	"github.com/joho/godotenv" // добавьте этот импорт
)

func main() {
	// Загрузка переменных окружения из .env файла
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Инициализация БД
	db.Init(db.Config{DBPath: "./data.db"})
	defer db.Close()

	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	redirectURL := os.Getenv("GITHUB_REDIRECT_URL")

	if clientID != "" && clientSecret != "" {
		if redirectURL == "" {
			redirectURL = "http://localhost:8080/api/auth/github/callback"
		}
		server.InitOAuth(clientID, clientSecret, redirectURL)
		log.Println("GitHub OAuth initialized")
	} else {
		log.Println("GitHub OAuth not configured")
	}

	// Запуск сервера
	server.Init(server.Config{
		Host: "localhost",
		Port: "8080",
	})
	server.Start()
}
