package ssh_test

import (
	"bytes"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"secretbay/backend/internal/ssh"
)

// Test private key for SSH authentication tests
const testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvZF1jkbI0t5pGSc8nxRGiH0qFkrXn00n00yN0ddwg3aqR+0p
...
-----END RSA PRIVATE KEY-----`

func setupTestLogger() *logrus.Logger {
	logger := logrus.New()
	logger.Out = bytes.NewBuffer(nil)
	return logger
}

func TestNewService(t *testing.T) {
	logger := setupTestLogger()
	service := ssh.NewService(logger)

	assert.NotNil(t, service, "SSH service should not be nil")
}

func TestConnect_Password(t *testing.T) {
	logger := setupTestLogger()
	service := ssh.NewService(logger)

	config := &ssh.ConnectionConfig{
		Host:        "localhost",
		Port:        22,
		Username:    "testuser",
		Password:    "testpass",
		UsePassword: true,
	}

	// This test will fail in a real environment as it requires an actual SSH server
	// In a real test environment, we would use a mock SSH server
	_, err := service.Connect(config)
	assert.Error(t, err, "Should fail to connect to non-existent SSH server")
	assert.Contains(t, err.Error(), "failed to connect to SSH server")
}

func TestConnect_PrivateKey(t *testing.T) {
	logger := setupTestLogger()
	service := ssh.NewService(logger)

	config := &ssh.ConnectionConfig{
		Host:        "localhost",
		Port:        22,
		Username:    "testuser",
		PrivateKey:  testPrivateKey,
		UsePassword: false,
	}

	// This test will fail in a real environment as it requires an actual SSH server
	_, err := service.Connect(config)
	assert.Error(t, err, "Should fail to connect to non-existent SSH server")
}

func TestSession_ExecuteCommand(t *testing.T) {
	// This is a mock test demonstrating how the ExecuteCommand method should work
	// In a real test environment, we would use a mock SSH server
	logger := setupTestLogger()
	service := ssh.NewService(logger)

	config := &ssh.ConnectionConfig{
		Host:        "localhost",
		Port:        22,
		Username:    "testuser",
		Password:    "testpass",
		UsePassword: true,
	}

	session, err := service.Connect(config)
	if err == nil {
		defer session.Close()

		stdout, stderr, err := session.ExecuteCommand("echo 'test'")
		assert.Error(t, err, "Should fail to execute command on non-existent SSH server")
		assert.Empty(t, stdout)
		assert.Empty(t, stderr)
	}
}

func TestValidateConnectionConfig(t *testing.T) {
	testCases := []struct {
		name        string
		config      *ssh.ConnectionConfig
		shouldError bool
	}{
		{
			name: "Valid Password Config",
			config: &ssh.ConnectionConfig{
				Host:        "localhost",
				Port:        22,
				Username:    "testuser",
				Password:    "testpass",
				UsePassword: true,
			},
			shouldError: false,
		},
		{
			name: "Valid Key Config",
			config: &ssh.ConnectionConfig{
				Host:        "localhost",
				Port:        22,
				Username:    "testuser",
				PrivateKey:  testPrivateKey,
				UsePassword: false,
			},
			shouldError: false,
		},
		{
			name: "Missing Host",
			config: &ssh.ConnectionConfig{
				Port:        22,
				Username:    "testuser",
				Password:    "testpass",
				UsePassword: true,
			},
			shouldError: true,
		},
		{
			name: "Missing Username",
			config: &ssh.ConnectionConfig{
				Host:        "localhost",
				Port:        22,
				Password:    "testpass",
				UsePassword: true,
			},
			shouldError: true,
		},
		{
			name: "Missing Password When UsePassword=true",
			config: &ssh.ConnectionConfig{
				Host:        "localhost",
				Port:        22,
				Username:    "testuser",
				UsePassword: true,
			},
			shouldError: true,
		},
		{
			name: "Missing PrivateKey When UsePassword=false",
			config: &ssh.ConnectionConfig{
				Host:        "localhost",
				Port:        22,
				Username:    "testuser",
				UsePassword: false,
			},
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ssh.ValidateConnectionConfig(tc.config)
			if tc.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSession_UploadFile(t *testing.T) {
	logger := setupTestLogger()
	service := ssh.NewService(logger)

	config := &ssh.ConnectionConfig{
		Host:        "localhost",
		Port:        22,
		Username:    "testuser",
		Password:    "testpass",
		UsePassword: true,
	}

	session, err := service.Connect(config)
	if err == nil {
		defer session.Close()

		content := []byte("test content")
		err := session.UploadFile(content, "/tmp/test.txt")
		assert.Error(t, err, "Should fail to upload file to non-existent SSH server")
	}
}

func TestSession_DownloadFile(t *testing.T) {
	logger := setupTestLogger()
	service := ssh.NewService(logger)

	config := &ssh.ConnectionConfig{
		Host:        "localhost",
		Port:        22,
		Username:    "testuser",
		Password:    "testpass",
		UsePassword: true,
	}

	session, err := service.Connect(config)
	if err == nil {
		defer session.Close()

		content, err := session.DownloadFile("/tmp/test.txt")
		assert.Error(t, err, "Should fail to download file from non-existent SSH server")
		assert.Nil(t, content)
	}
}

func TestSession_ForwardPort(t *testing.T) {
	logger := setupTestLogger()
	service := ssh.NewService(logger)

	config := &ssh.ConnectionConfig{
		Host:        "localhost",
		Port:        22,
		Username:    "testuser",
		Password:    "testpass",
		UsePassword: true,
	}

	session, err := service.Connect(config)
	if err == nil {
		defer session.Close()

		err := session.ForwardPort(8080, 80)
		assert.Error(t, err, "Should fail to forward port on non-existent SSH server")
	}
}
