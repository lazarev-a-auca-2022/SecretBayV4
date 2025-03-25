// Package api handles HTTP requests for the SecretBay API
package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"secretbay/backend/internal/ssh"
	"secretbay/backend/internal/vpn"
)

// Handler manages HTTP requests for the API
type Handler struct {
	logger     *logrus.Logger
	configPath string
	vpnService vpn.ServiceInterface
	sshService ssh.ServiceInterface
	jwtSecret  []byte
}

// NewHandler creates a new API handler
func NewHandler(logger *logrus.Logger, configPath string) *Handler {
	sshService := ssh.NewService(logger)
	vpnService := vpn.NewService(logger, configPath, sshService)

	// Get JWT secret from environment or use default
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("secretbay-default-jwt-secret-change-in-production")
		logger.Warn("Using default JWT secret - consider setting JWT_SECRET environment variable")
	}

	return &Handler{
		logger:     logger,
		configPath: configPath,
		vpnService: vpnService,
		sshService: sshService,
		jwtSecret:  jwtSecret,
	}
}

// NewHandlerWithServices creates a new API handler with provided service implementations
// This is primarily used for testing with mock services
func NewHandlerWithServices(logger *logrus.Logger, configPath string, vpnService vpn.ServiceInterface, sshService ssh.ServiceInterface) *Handler {
	// Get JWT secret from environment or use default
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("secretbay-default-jwt-secret-change-in-production")
		logger.Warn("Using default JWT secret - consider setting JWT_SECRET environment variable")
	}

	return &Handler{
		logger:     logger,
		configPath: configPath,
		vpnService: vpnService,
		sshService: sshService,
		jwtSecret:  jwtSecret,
	}
}

// GenerateJWTForTest creates a JWT token for testing purposes
func (h *Handler) GenerateJWTForTest(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"iat":      time.Now().Unix(),
	})

	return token.SignedString(h.jwtSecret)
}

// RegisterRoutes sets up the API routes
func (h *Handler) RegisterRoutes(router *mux.Router) {
	// Public endpoints
	router.HandleFunc("/health", h.healthCheck).Methods(http.MethodGet)
	router.HandleFunc("/authenticate", h.authenticate).Methods(http.MethodPost)

	// Protected endpoints
	protected := router.NewRoute().Subrouter()
	protected.Use(h.authMiddleware)
	protected.HandleFunc("/configure", h.configureVPN).Methods(http.MethodPost)
	protected.HandleFunc("/status", h.checkStatus).Methods(http.MethodGet)
}

// healthCheck handles health check requests
func (h *Handler) healthCheck(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

// checkStatus returns the current server status
func (h *Handler) checkStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"server_version": "1.0.0",
		"uptime":         time.Now().Unix(),
		"status":         "operational",
	}

	h.sendJSONResponse(w, http.StatusOK, status)
}

// VPNRequest represents the request to configure a VPN
type VPNRequest struct {
	ServerIP       string `json:"server_ip"`
	Username       string `json:"username"`
	AuthMethod     string `json:"auth_method"`
	AuthCredential string `json:"auth_credential"`
	VPNType        string `json:"vpn_type"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// configureVPN handles VPN configuration requests
func (h *Handler) configureVPN(w http.ResponseWriter, r *http.Request) {
	// Validate Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		h.sendErrorResponse(w, http.StatusBadRequest, "Invalid request format: Content-Type must be application/json", nil)
		return
	}

	var req VPNRequest

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, http.StatusBadRequest, "Invalid request format: failed to decode JSON", err)
		return
	}

	// Validate request fields
	if req.ServerIP == "" || req.Username == "" || req.AuthMethod == "" || req.AuthCredential == "" || req.VPNType == "" {
		h.sendErrorResponse(w, http.StatusBadRequest, "Missing required fields", nil)
		return
	}

	// Ensure VPN type is valid
	if req.VPNType != "ios" && req.VPNType != "openvpn" {
		h.sendErrorResponse(w, http.StatusBadRequest, "Invalid VPN type: must be 'ios' or 'openvpn'", nil)
		return
	}

	// Ensure auth method is valid
	if req.AuthMethod != "password" && req.AuthMethod != "key" {
		h.sendErrorResponse(w, http.StatusBadRequest, "Invalid auth method: must be 'password' or 'key'", nil)
		return
	}

	// Configure VPN
	h.logger.WithFields(logrus.Fields{
		"server_ip": req.ServerIP,
		"username":  req.Username,
		"vpn_type":  req.VPNType,
	}).Info("Starting VPN configuration")

	result, err := h.vpnService.Configure(&vpn.ConfigRequest{
		ServerIP:       req.ServerIP,
		Username:       req.Username,
		AuthMethod:     req.AuthMethod,
		AuthCredential: req.AuthCredential,
		VPNType:        req.VPNType,
	})

	if err != nil {
		// Handle SSH connection errors gracefully
		if strings.Contains(err.Error(), "failed to connect to server") {
			h.sendErrorResponse(w, http.StatusBadGateway, "Failed to connect to VPN server", err)
			return
		}
		h.sendErrorResponse(w, http.StatusInternalServerError, "Failed to configure VPN", err)
		return
	}

	h.sendSuccessResponse(w, http.StatusOK, "VPN configured successfully", result)
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	Token string `json:"token"`
}

// authenticate handles authentication requests
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendErrorResponse(w, http.StatusBadRequest, "Invalid request format", err)
		return
	}

	// In a production environment, this would validate credentials against a database
	// For this implementation, we're using a simple check with environment variables or defaults
	validUsername := os.Getenv("ADMIN_USERNAME")
	validPassword := os.Getenv("ADMIN_PASSWORD")

	if validUsername == "" {
		validUsername = "admin"
	}

	if validPassword == "" {
		validPassword = "secretbay"
	}

	if req.Username != validUsername || req.Password != validPassword {
		h.sendErrorResponse(w, http.StatusUnauthorized, "Invalid credentials", nil)
		return
	}

	// Create JWT token with expiration
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": req.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"iat":      time.Now().Unix(),
	})

	// Sign the token with the secret key
	tokenString, err := token.SignedString(h.jwtSecret)
	if err != nil {
		h.sendErrorResponse(w, http.StatusInternalServerError, "Failed to generate token", err)
		return
	}

	h.sendSuccessResponse(w, http.StatusOK, "Authentication successful", AuthResponse{Token: tokenString})
}

// authMiddleware authenticates requests using JWT
func (h *Handler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			h.sendErrorResponse(w, http.StatusUnauthorized, "Authorization header required", nil)
			return
		}

		// Remove "Bearer " prefix if present
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		// Parse token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return h.jwtSecret, nil
		})

		if err != nil {
			h.sendErrorResponse(w, http.StatusUnauthorized, "Invalid token", err)
			return
		}

		if !token.Valid {
			h.sendErrorResponse(w, http.StatusUnauthorized, "Token is invalid or expired", nil)
			return
		}

		// Token is valid, continue to the next handler
		next.ServeHTTP(w, r)
	})
}

// sendJSONResponse sends a JSON response with the given status code and data
func (h *Handler) sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

// sendErrorResponse sends an error response
func (h *Handler) sendErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	response := APIResponse{
		Success: false,
		Message: message,
	}

	if err != nil {
		response.Error = err.Error()
		h.logger.WithError(err).Error(message)
	} else {
		h.logger.Error(message)
	}

	h.sendJSONResponse(w, statusCode, response)
}

// sendSuccessResponse sends a success response
func (h *Handler) sendSuccessResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	response := APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	h.logger.WithField("data", data).Info(message)
	h.sendJSONResponse(w, statusCode, response)
}
