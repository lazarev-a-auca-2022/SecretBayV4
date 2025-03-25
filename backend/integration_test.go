package backend_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"secretbay/backend/internal/api"
	"secretbay/backend/internal/ssh"
	"secretbay/backend/internal/vpn"
)

// MockSSHSession implements ssh.Session for testing
type MockSSHSession struct {
	mock.Mock
}

func (m *MockSSHSession) ExecuteCommand(command string) (string, string, error) {
	args := m.Called(command)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockSSHSession) ExecuteScript(script string) (string, string, error) {
	args := m.Called(script)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockSSHSession) UploadFile(content []byte, remotePath string) error {
	args := m.Called(content, remotePath)
	return args.Error(0)
}

func (m *MockSSHSession) DownloadFile(remotePath string) ([]byte, error) {
	args := m.Called(remotePath)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSSHSession) Close() {
	m.Called()
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

// testServer represents a test instance of the API server
type testServer struct {
	router     *mux.Router
	apiHandler *api.Handler
	sshService *MockSSHService
	vpnService *vpn.Service
	logger     *logrus.Logger
}

// setupTestServer creates a test server with mocked SSH service
func setupTestServer(t *testing.T) *testServer {
	// Create a test logger
	logger := logrus.New()
	logger.Out = bytes.NewBuffer(nil)

	// Set up test configuration paths
	tempDir, err := os.MkdirTemp("", "secretbay-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	// Create test configuration files
	err = os.MkdirAll(filepath.Join(tempDir, "templates"), 0755)
	require.NoError(t, err)

	// Write test configuration templates with placeholders
	openvpnScript := []byte(`#!/bin/bash
# OpenVPN setup script template
apt-get update
apt-get install -y openvpn
echo "Test OpenVPN config for {{SERVER_IP}} and {{CLIENT_NAME}}" > /tmp/client.ovpn`)

	strongswanScript := []byte(`#!/bin/bash
# StrongSwan setup script template
apt-get update
apt-get install -y strongswan
echo "Test StrongSwan config for {{SERVER_IP}} with user {{VPN_USERNAME}}" > /tmp/ios-vpn.mobileconfig`)

	err = os.WriteFile(filepath.Join(tempDir, "templates", "openvpn-setup.sh"), openvpnScript, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tempDir, "templates", "strongswan-setup.sh"), strongswanScript, 0644)
	require.NoError(t, err)

	// Set up test environment variables
	t.Setenv("ADMIN_USERNAME", "testadmin")
	t.Setenv("ADMIN_PASSWORD", "testpass123")
	t.Setenv("JWT_SECRET", "test-jwt-secret")

	// Create mock SSH service
	mockSSHService := new(MockSSHService)
	mockSession := new(MockSSHSession)

	// Set up mock expectations
	mockSSHService.On("Connect", mock.MatchedBy(func(config *ssh.ConnectionConfig) bool {
		return true // Accept any config for testing
	})).Return(mockSession, nil)

	// Mock OS check
	mockSession.On("ExecuteCommand", "cat /etc/os-release | grep 'ID=ubuntu'").Return("ID=ubuntu", "", nil)

	// Mock script execution
	mockSession.On("ExecuteScript", mock.MatchedBy(func(script string) bool {
		return strings.Contains(script, "apt-get install") // Basic script validation
	})).Return("Success", "", nil)

	// Mock file operations
	mockSession.On("DownloadFile", "/tmp/client.ovpn").Return([]byte("test openvpn config"), nil)
	mockSession.On("DownloadFile", "/tmp/ios-vpn.mobileconfig").Return([]byte("test strongswan config"), nil)
	mockSession.On("ExecuteCommand", mock.MatchedBy(func(cmd string) bool {
		return strings.Contains(cmd, "rm -f /tmp/") // File cleanup
	})).Return("", "", nil)

	// Mock security commands
	mockSession.On("ExecuteCommand", mock.MatchedBy(func(cmd string) bool {
		return strings.Contains(cmd, "apt-get") ||
			strings.Contains(cmd, "ufw") ||
			strings.Contains(cmd, "sshd") ||
			strings.Contains(cmd, "history") ||
			strings.Contains(cmd, "chpasswd")
	})).Return("", "", nil)

	mockSession.On("UploadFile", mock.Anything, "/etc/logrotate.d/vpn").Return(nil)
	mockSession.On("Close").Return()

	// Create services with mock SSH
	vpnService := vpn.NewService(logger, tempDir, mockSSHService)
	apiHandler := api.NewHandlerWithServices(logger, tempDir, vpnService, mockSSHService)

	// Set up router
	router := mux.NewRouter()
	apiHandler.RegisterRoutes(router.PathPrefix("/api").Subrouter())

	return &testServer{
		router:     router,
		apiHandler: apiHandler,
		sshService: mockSSHService,
		vpnService: vpnService,
		logger:     logger,
	}
}

func TestFullWorkflow(t *testing.T) {
	server := setupTestServer(t)

	// Step 1: Test authentication
	t.Run("Authentication", func(t *testing.T) {
		reqBody := map[string]string{
			"username": "testadmin",
			"password": "testpass123",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/authenticate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.True(t, response["success"].(bool))
		assert.Contains(t, response, "data")

		data := response["data"].(map[string]interface{})
		assert.Contains(t, data, "token")
		token := data["token"].(string)
		assert.NotEmpty(t, token)

		// Store token for next steps
		t.Setenv("TEST_AUTH_TOKEN", token)
	})

	// Step 2: Test health check endpoint
	t.Run("Health Check", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "ok", response["status"])
		assert.Contains(t, response, "timestamp")
	})

	// Step 3: Test VPN configuration (OpenVPN)
	t.Run("Configure OpenVPN", func(t *testing.T) {
		token := os.Getenv("TEST_AUTH_TOKEN")
		require.NotEmpty(t, token)

		reqBody := map[string]string{
			"server_ip":       "192.168.1.100",
			"username":        "testuser",
			"auth_method":     "password",
			"auth_credential": "userpass123",
			"vpn_type":        "openvpn",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/configure", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		// Since we don't have a real SSH server, this should fail gracefully
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.False(t, response["success"].(bool))
		assert.Contains(t, response["message"], "Failed to configure VPN")
	})

	// Step 4: Test VPN configuration (iOS/StrongSwan)
	t.Run("Configure StrongSwan", func(t *testing.T) {
		token := os.Getenv("TEST_AUTH_TOKEN")
		require.NotEmpty(t, token)

		reqBody := map[string]string{
			"server_ip":       "192.168.1.100",
			"username":        "testuser",
			"auth_method":     "password",
			"auth_credential": "userpass123",
			"vpn_type":        "ios",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/configure", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		// Since we don't have a real SSH server, this should fail gracefully
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.False(t, response["success"].(bool))
		assert.Contains(t, response["message"], "Failed to configure VPN")
	})

	// Step 5: Test invalid authentication
	t.Run("Invalid Authentication", func(t *testing.T) {
		reqBody := map[string]string{
			"username": "testadmin",
			"password": "wrongpass",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/authenticate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.False(t, response["success"].(bool))
		assert.Contains(t, response["message"], "Invalid credentials")
	})

	// Step 6: Test unauthorized access
	t.Run("Unauthorized Access", func(t *testing.T) {
		reqBody := map[string]string{
			"server_ip":       "192.168.1.100",
			"username":        "testuser",
			"auth_method":     "password",
			"auth_credential": "userpass123",
			"vpn_type":        "openvpn",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/configure", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		// No authentication token provided
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.False(t, response["success"].(bool))
		assert.Contains(t, response["message"], "Authorization header required")
	})
}

func TestInvalidRequests(t *testing.T) {
	server := setupTestServer(t)

	// Get authentication token for protected endpoints
	token := getTestAuthToken(t, server.router)

	testCases := []struct {
		name          string
		endpoint      string
		method        string
		contentType   string
		body          map[string]string
		authenticated bool
		expectedCode  int
		expectedError string
	}{
		{
			name:        "Missing Required Fields",
			endpoint:    "/api/configure",
			method:      http.MethodPost,
			contentType: "application/json",
			body: map[string]string{
				"server_ip": "192.168.1.100",
				// Missing other required fields
			},
			authenticated: true,
			expectedCode:  http.StatusBadRequest,
			expectedError: "Missing required fields",
		},
		{
			name:        "Invalid VPN Type",
			endpoint:    "/api/configure",
			method:      http.MethodPost,
			contentType: "application/json",
			body: map[string]string{
				"server_ip":       "192.168.1.100",
				"username":        "testuser",
				"auth_method":     "password",
				"auth_credential": "userpass123",
				"vpn_type":        "invalid",
			},
			authenticated: true,
			expectedCode:  http.StatusBadRequest,
			expectedError: "Invalid VPN type",
		},
		{
			name:        "Invalid Auth Method",
			endpoint:    "/api/configure",
			method:      http.MethodPost,
			contentType: "application/json",
			body: map[string]string{
				"server_ip":       "192.168.1.100",
				"username":        "testuser",
				"auth_method":     "invalid",
				"auth_credential": "userpass123",
				"vpn_type":        "openvpn",
			},
			authenticated: true,
			expectedCode:  http.StatusBadRequest,
			expectedError: "Invalid auth method",
		},
		{
			name:        "Invalid Content Type",
			endpoint:    "/api/configure",
			method:      http.MethodPost,
			contentType: "text/plain",
			body: map[string]string{
				"server_ip": "192.168.1.100",
			},
			authenticated: true,
			expectedCode:  http.StatusBadRequest,
			expectedError: "Invalid request format: Content-Type must be application/json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.body)
			require.NoError(t, err)

			req := httptest.NewRequest(tc.method, tc.endpoint, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", tc.contentType)
			if tc.authenticated {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			}
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedCode, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.False(t, response["success"].(bool))
			assert.Contains(t, response["message"], tc.expectedError)
		})
	}
}

// Helper function to get an authentication token for testing
func getTestAuthToken(t *testing.T, router *mux.Router) string {
	reqBody := map[string]string{
		"username": "testadmin",
		"password": "testpass123",
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/authenticate", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	data := response["data"].(map[string]interface{})
	return data["token"].(string)
}
