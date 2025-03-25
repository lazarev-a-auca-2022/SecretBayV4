// Package ssh provides functionality for connecting to remote servers via SSH
package ssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// ServiceInterface defines the interface for SSH service operations
type ServiceInterface interface {
	Connect(config *ConnectionConfig) (*Session, error)
}

// Service handles SSH connections and commands
type Service struct {
	logger *logrus.Logger
}

// NewService creates a new SSH service
func NewService(logger *logrus.Logger) *Service {
	return &Service{
		logger: logger,
	}
}

// ConnectionConfig represents the configuration for an SSH connection
type ConnectionConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	PrivateKey  string
	UsePassword bool
	Timeout     time.Duration
}

// ValidateConnectionConfig validates the SSH connection configuration
func ValidateConnectionConfig(config *ConnectionConfig) error {
	if config == nil {
		return fmt.Errorf("connection config cannot be nil")
	}

	if config.Host == "" {
		return fmt.Errorf("host is required")
	}

	if config.Username == "" {
		return fmt.Errorf("username is required")
	}

	if config.UsePassword && config.Password == "" {
		return fmt.Errorf("password is required when using password authentication")
	}

	if !config.UsePassword && config.PrivateKey == "" {
		return fmt.Errorf("private key is required when using key authentication")
	}

	return nil
}

// Session represents an SSH session
type Session struct {
	client  *ssh.Client
	session *ssh.Session
	stdout  bytes.Buffer
	stderr  bytes.Buffer
}

// Connect establishes an SSH connection to a server
func (s *Service) Connect(config *ConnectionConfig) (*Session, error) {
	// Set default port and timeout if not provided
	if config.Port == 0 {
		config.Port = 22
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Create SSH client configuration
	sshConfig := &ssh.ClientConfig{
		User:            config.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         config.Timeout,
	}

	// Set authentication method based on provided credentials
	if config.UsePassword {
		sshConfig.Auth = []ssh.AuthMethod{
			ssh.Password(config.Password),
		}
	} else {
		// Parse private key
		key, err := ssh.ParsePrivateKey([]byte(config.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		sshConfig.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(key),
		}
	}

	// Connect to the SSH server
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH server: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"host":     config.Host,
		"port":     config.Port,
		"username": config.Username,
	}).Info("SSH connection established")

	// Create a new SSH session
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create SSH session: %w", err)
	}

	// Set up stdout and stderr
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	return &Session{
		client:  client,
		session: session,
		stdout:  stdout,
		stderr:  stderr,
	}, nil
}

// ExecuteCommand executes a command on the SSH session
func (s *Session) ExecuteCommand(command string) (string, string, error) {
	// Create a new session
	session, err := s.client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Capture stdout and stderr
	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	// Execute the command
	if err := session.Run(command); err != nil {
		return stdoutBuf.String(), stderrBuf.String(), fmt.Errorf("command execution failed: %w", err)
	}

	return stdoutBuf.String(), stderrBuf.String(), nil
}

// ExecuteScript uploads and executes a script on the remote server
func (s *Session) ExecuteScript(script string) (string, string, error) {
	// Create a new session for file transfer
	transferSession, err := s.client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create file transfer session: %w", err)
	}
	defer transferSession.Close()

	// Set up file transfer pipe
	stdin, err := transferSession.StdinPipe()
	if err != nil {
		return "", "", fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Command to receive the file and make it executable
	tempFilePath := "/tmp/secretbay_script.sh"
	transferCmd := fmt.Sprintf("cat > %s && chmod +x %s", tempFilePath, tempFilePath)

	if err := transferSession.Start(transferCmd); err != nil {
		return "", "", fmt.Errorf("failed to start file transfer: %w", err)
	}

	// Write the script to the pipe
	if _, err := io.WriteString(stdin, script); err != nil {
		return "", "", fmt.Errorf("failed to write script to pipe: %w", err)
	}

	if err := stdin.Close(); err != nil {
		return "", "", fmt.Errorf("failed to close stdin pipe: %w", err)
	}

	// Wait for the file transfer to complete
	if err := transferSession.Wait(); err != nil {
		return "", "", fmt.Errorf("failed to upload script: %w", err)
	}

	// Execute the script
	stdout, stderr, err := s.ExecuteCommand(tempFilePath)

	// Clean up
	cleanupSession, err := s.client.NewSession()
	if err == nil {
		defer cleanupSession.Close()
		cleanupSession.Run(fmt.Sprintf("rm -f %s", tempFilePath))
	}
	// We return the output and error from the script execution
	return stdout, stderr, err
}

// UploadFile uploads a file to the remote server
func (s *Session) UploadFile(content []byte, remotePath string) error {
	// Create a new session for file transfer
	transferSession, err := s.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create file transfer session: %w", err)
	}
	defer transferSession.Close()

	// Set up file transfer pipe
	stdin, err := transferSession.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Command to receive the file
	if err := transferSession.Start(fmt.Sprintf("cat > %s", remotePath)); err != nil {
		return fmt.Errorf("failed to start file transfer: %w", err)
	}

	// Write the file content to the pipe
	if _, err := stdin.Write(content); err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}

	if err := stdin.Close(); err != nil {
		return fmt.Errorf("failed to close stdin pipe: %w", err)
	}

	// Wait for the file transfer to complete
	return transferSession.Wait()
}

// DownloadFile downloads a file from the remote server
func (s *Session) DownloadFile(remotePath string) ([]byte, error) {
	// Create a new session for file download
	downloadSession, err := s.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create file download session: %w", err)
	}
	defer downloadSession.Close()

	// Get file content
	output, err := downloadSession.CombinedOutput(fmt.Sprintf("cat %s", remotePath))
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %w", err)
	}

	return output, nil
}

// ForwardPort sets up port forwarding from the local machine to the remote server
func (s *Session) ForwardPort(localPort, remotePort int) error {
	// Create a local TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", localPort))
	if err != nil {
		return fmt.Errorf("failed to listen on local port: %w", err)
	}

	// Accept connections in a goroutine
	go func() {
		for {
			localConn, err := listener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					fmt.Printf("Failed to accept connection: %v\n", err)
				}
				return
			}

			// Open a connection to the remote port
			remoteConn, err := s.client.Dial("tcp", fmt.Sprintf("localhost:%d", remotePort))
			if err != nil {
				fmt.Printf("Failed to connect to remote port: %v\n", err)
				localConn.Close()
				continue
			}

			// Copy data between the connections
			go func() {
				io.Copy(remoteConn, localConn)
				localConn.Close()
				remoteConn.Close()
			}()

			go func() {
				io.Copy(localConn, remoteConn)
				localConn.Close()
				remoteConn.Close()
			}()
		}
	}()

	return nil
}

// Close closes the SSH session and client
func (s *Session) Close() {
	if s.session != nil {
		s.session.Close()
	}
	if s.client != nil {
		s.client.Close()
	}
}
