package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"secretbay/backend/internal/api"
	"secretbay/backend/internal/ssh"
	"secretbay/backend/internal/vpn"
)

// MockVPNService implements vpn.ServiceInterface for testing
type MockVPNService struct {
	mock.Mock
}

func (m *MockVPNService) Configure(req *vpn.ConfigRequest) (*vpn.ConfigResult, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*vpn.ConfigResult), args.Error(1)
}

func (m *MockVPNService) GeneratePassword(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

// MockSSHService implements ssh.ServiceInterface for testing
type MockSSHService struct {
	mock.Mock
}

func (m *MockSSHService) Connect(config *ssh.ConnectionConfig) (*ssh.Session, error) {
	args := m.Called(config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ssh.Session), args.Error(1)
}

// Custom assertion function to validate JSON responses
func assertJSONResponse(t *testing.T, response *httptest.ResponseRecorder, expectedStatus int, expectedBody map[string]interface{}) {
	assert.Equal(t, expectedStatus, response.Code)
	assert.Equal(t, "application/json", response.Header().Get("Content-Type"))

	var actualBody map[string]interface{}
	err := json.Unmarshal(response.Body.Bytes(), &actualBody)
	assert.NoError(t, err)

	for key, expectedValue := range expectedBody {
		assert.Equal(t, expectedValue, actualBody[key], "Response JSON does not match expected value for key: %s", key)
	}
}

func setupTestHandler() (*api.Handler, *MockVPNService, *MockSSHService) {
	// Create mock services
	mockVPNService := new(MockVPNService)
	mockSSHService := new(MockSSHService)

	// Create a test logger that discards output
	logger := logrus.New()
	logger.Out = bytes.NewBuffer(nil)

	// Create test handler
	handler := api.NewHandlerWithServices(logger, "./test_configs", mockVPNService, mockSSHService)

	return handler, mockVPNService, mockSSHService
}

func TestHealthCheck(t *testing.T) {
	// Set up handler
	handler, _, _ := setupTestHandler()

	// Create a request
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()

	// Call health check handler
	router := mux.NewRouter()
	handler.RegisterRoutes(router.PathPrefix("/api").Subrouter())
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestAuthenticate_Success(t *testing.T) {
	// Set up handler
	handler, _, _ := setupTestHandler()

	// Set environment variables for testing
	t.Setenv("ADMIN_USERNAME", "testuser")
	t.Setenv("ADMIN_PASSWORD", "testpass")

	// Create request body
	authRequest := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}

	reqBody, _ := json.Marshal(authRequest)
	req := httptest.NewRequest(http.MethodPost, "/api/authenticate", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Call authentication handler
	router := mux.NewRouter()
	handler.RegisterRoutes(router.PathPrefix("/api").Subrouter())
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.True(t, response["success"].(bool))
	assert.Contains(t, response, "data")

	// Check if token exists in response
	data := response["data"].(map[string]interface{})
	assert.Contains(t, data, "token")
	assert.NotEmpty(t, data["token"].(string))
}

func TestAuthenticate_Failure(t *testing.T) {
	// Set up handler
	handler, _, _ := setupTestHandler()

	// Set environment variables for testing
	t.Setenv("ADMIN_USERNAME", "testuser")
	t.Setenv("ADMIN_PASSWORD", "testpass")

	// Create request with incorrect credentials
	authRequest := map[string]string{
		"username": "testuser",
		"password": "wrongpass",
	}

	reqBody, _ := json.Marshal(authRequest)
	req := httptest.NewRequest(http.MethodPost, "/api/authenticate", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Call authentication handler
	router := mux.NewRouter()
	handler.RegisterRoutes(router.PathPrefix("/api").Subrouter())
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.False(t, response["success"].(bool))
	assert.Contains(t, response["message"], "Invalid credentials")
}

func TestConfigureVPN_Success(t *testing.T) {
	// Set up handler
	handler, mockVPNService, _ := setupTestHandler()

	// Set up mock VPN service
	mockResult := &vpn.ConfigResult{
		Config:         "test config content",
		ConfigFileName: "test.ovpn",
		NewPassword:    "newpassword123",
		ConnectionInfo: "Test connection info",
	}

	mockVPNService.On("Configure", mock.Anything).Return(mockResult, nil)

	// Create JWT token for authentication
	token, _ := handler.GenerateJWTForTest("testuser")

	// Create request body
	vpnRequest := map[string]string{
		"server_ip":       "192.168.1.1",
		"username":        "root",
		"auth_method":     "password",
		"auth_credential": "password123",
		"vpn_type":        "openvpn",
	}

	reqBody, _ := json.Marshal(vpnRequest)
	req := httptest.NewRequest(http.MethodPost, "/api/configure", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	w := httptest.NewRecorder()

	// Call configure VPN handler
	router := mux.NewRouter()
	handler.RegisterRoutes(router.PathPrefix("/api").Subrouter())
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.True(t, response["success"].(bool))

	// Verify mock was called with correct parameters
	mockVPNService.AssertCalled(t, "Configure", mock.MatchedBy(func(req *vpn.ConfigRequest) bool {
		return req.ServerIP == "192.168.1.1" &&
			req.Username == "root" &&
			req.AuthMethod == "password" &&
			req.AuthCredential == "password123" &&
			req.VPNType == "openvpn"
	}))
}

func TestConfigureVPN_InvalidRequest(t *testing.T) {
	// Set up handler
	handler, _, _ := setupTestHandler()

	// Create JWT token for authentication
	token, _ := handler.GenerateJWTForTest("testuser")

	// Create request with missing fields
	vpnRequest := map[string]string{
		"server_ip": "192.168.1.1",
		// Missing other required fields
	}

	reqBody, _ := json.Marshal(vpnRequest)
	req := httptest.NewRequest(http.MethodPost, "/api/configure", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	w := httptest.NewRecorder()

	// Call configure VPN handler
	router := mux.NewRouter()
	handler.RegisterRoutes(router.PathPrefix("/api").Subrouter())
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.False(t, response["success"].(bool))
	assert.Contains(t, response["message"], "Missing required fields")
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	// Set up handler
	handler, _, _ := setupTestHandler()

	// Create request without token
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()

	// Call protected endpoint
	router := mux.NewRouter()
	handler.RegisterRoutes(router.PathPrefix("/api").Subrouter())
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.False(t, response["success"].(bool))
	assert.Contains(t, response["message"], "Authorization header required")
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	// Set up handler
	handler, _, _ := setupTestHandler()

	// Create request with invalid token
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "invalid-token")
	w := httptest.NewRecorder()

	// Call protected endpoint
	router := mux.NewRouter()
	handler.RegisterRoutes(router.PathPrefix("/api").Subrouter())
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.False(t, response["success"].(bool))
	assert.Contains(t, response["message"], "Invalid token")
}
