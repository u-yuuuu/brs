package server

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"
)

//go:embed static/*.html
var staticFiles embed.FS

var httpServer *http.Server
var templates *template.Template

type Config struct {
	Host string
	Port string
}

func Init(cfg Config) {
	// Загружаем шаблоны
	loadTemplates()

	httpServer = &http.Server{
		Addr:         cfg.Host + ":" + cfg.Port,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	setupRoutes()
}

func loadTemplates() {
	var err error
	templates, err = template.ParseFS(staticFiles, "static/*.html")
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}
}

// Start запускает HTTP сервер
func Start() error {
	if httpServer == nil {
		return fmt.Errorf("server not initialized. Call Init() first")
	}

	log.Printf("Server starting on http://%s", httpServer.Addr)
	return httpServer.ListenAndServe()
}

// Shutdown gracefully останавливает сервер
func Shutdown(ctx context.Context) error {
	if httpServer == nil {
		return nil
	}

	log.Println("Server shutting down...")
	return httpServer.Shutdown(ctx)
}
