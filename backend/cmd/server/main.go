// Package main is the entry point for the SecretBay VPN configuration server
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"

	"secretbay/backend/internal/api"
)

var (
	port        = flag.String("port", "8443", "Server port")
	tlsCertPath = flag.String("cert", "./certs/server.crt", "Path to TLS certificate")
	tlsKeyPath  = flag.String("key", "./certs/server.key", "Path to TLS key")
	logPath     = flag.String("log", "./logs/server.log", "Path to log file")
	configPath  = flag.String("config", "./configs", "Path to configuration templates")
)

func main() {
	// Initialize configuration
	flag.Parse()

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		fmt.Println("Warning: .env file not found or could not be loaded")
	}

	// Set up logging
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Ensure log directory exists
	logDir := filepath.Dir(*logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logger.Warnf("Could not create log directory: %v. Logging to stdout only", err)
	}

	// Log to file and stdout
	logFile, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logger.Warnf("Could not open log file: %v. Logging to stdout only", err)
	} else {
		mw := io.MultiWriter(os.Stdout, logFile)
		logger.SetOutput(mw)
		defer logFile.Close()
	}

	// Ensure certificate directory exists
	certDir := filepath.Dir(*tlsCertPath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		logger.Fatalf("Could not create certificate directory: %v", err)
	}

	// Check if certificates exist, generate self-signed certs if they don't
	if _, err := os.Stat(*tlsCertPath); os.IsNotExist(err) {
		logger.Info("TLS certificates not found, generating self-signed certificates")
		if err := generateSelfSignedCert(*tlsCertPath, *tlsKeyPath); err != nil {
			logger.Fatalf("Could not generate self-signed certificates: %v", err)
		}
	}

	// Set up HTTP router
	router := mux.NewRouter()

	// Set up API routes
	apiHandler := api.NewHandler(logger, *configPath)
	apiHandler.RegisterRoutes(router.PathPrefix("/api").Subrouter())

	// Serve frontend
	router.PathPrefix("/").Handler(
		http.StripPrefix("/", http.FileServer(http.Dir("./frontend"))),
	)

	// Add middleware
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	// Add logging middleware
	loggedRouter := handlers.LoggingHandler(logFile, corsMiddleware.Handler(router))

	// Configure TLS
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Create HTTPS server
	server := &http.Server{
		Addr:         ":" + *port,
		Handler:      loggedRouter,
		TLSConfig:    tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Infof("Starting SecretBay server on port %s", *port)

		if err := server.ListenAndServeTLS(*tlsCertPath, *tlsKeyPath); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Could not start server: %v", err)
		}
	}()

	// Set up graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	<-stop
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Server shutdown failed: %v", err)
	}

	logger.Info("Server gracefully stopped")
}

// generateSelfSignedCert creates a self-signed certificate for HTTPS
func generateSelfSignedCert(certPath, keyPath string) error {
	// Create directories if they don't exist
	certDir := filepath.Dir(certPath)
	keyDir := filepath.Dir(keyPath)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("could not create cert directory: %w", err)
	}

	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("could not create key directory: %w", err)
	}

	// Generate a self-signed certificate using openssl
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:4096",
		"-keyout", keyPath, "-out", certPath, "-days", "365", "-nodes",
		"-subj", "/CN=secretbay.local")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate: %w, output: %s", err, string(output))
	}

	return nil
}
