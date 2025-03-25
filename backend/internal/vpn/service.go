// Package vpn provides functionality for configuring VPN services on remote servers
package vpn

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"secretbay/backend/internal/ssh"
)

// ServiceInterface defines the interface for VPN service operations
type ServiceInterface interface {
	Configure(req *ConfigRequest) (*ConfigResult, error)
	GeneratePassword(length int) (string, error)
}

// Service handles VPN configuration operations
type Service struct {
	logger     *logrus.Logger
	configPath string
	sshService ssh.ServiceInterface
}

// NewService creates a new VPN service
func NewService(logger *logrus.Logger, configPath string, sshService ssh.ServiceInterface) *Service {
	return &Service{
		logger:     logger,
		configPath: configPath,
		sshService: sshService,
	}
}

// ConfigRequest represents a request to configure a VPN
type ConfigRequest struct {
	ServerIP       string
	Username       string
	AuthMethod     string
	AuthCredential string
	VPNType        string
}

// ConfigResult represents the result of a VPN configuration
type ConfigResult struct {
	Config         string `json:"config"`
	ConfigFileName string `json:"config_file_name"`
	NewPassword    string `json:"new_password,omitempty"`
	ConnectionInfo string `json:"connection_info"`
}

// Configure sets up a VPN server based on the provided configuration
func (s *Service) Configure(req *ConfigRequest) (*ConfigResult, error) {
	// Log start of configuration
	s.logger.WithFields(logrus.Fields{
		"server_ip": req.ServerIP,
		"username":  req.Username,
		"vpn_type":  req.VPNType,
	}).Info("Starting VPN configuration")

	// Generate new password for the server
	newPassword, err := s.GeneratePassword(16)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate password")
		return nil, fmt.Errorf("failed to generate new password: %w", err)
	}

	// Connect to the remote server
	sshConfig := &ssh.ConnectionConfig{
		Host:        req.ServerIP,
		Port:        22,
		Username:    req.Username,
		UsePassword: req.AuthMethod == "password",
	}

	if sshConfig.UsePassword {
		sshConfig.Password = req.AuthCredential
	} else {
		sshConfig.PrivateKey = req.AuthCredential
	}

	s.logger.WithField("config", sshConfig).Debug("Connecting to SSH server")
	session, err := s.sshService.Connect(sshConfig)
	if err != nil {
		s.logger.WithError(err).Error("Failed to connect to SSH server")
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer session.Close()

	// Check if server is running Ubuntu - make the check more robust
	osInfo, stderr, err := session.ExecuteCommand("cat /etc/os-release | grep 'ID=ubuntu'")
	if err != nil || !strings.Contains(strings.ToLower(osInfo), "id=ubuntu") {
		s.logger.WithFields(logrus.Fields{
			"osInfo": osInfo,
			"stderr": stderr,
			"error":  err,
		}).Error("Server OS check failed")
		return nil, fmt.Errorf("server must be running Ubuntu")
	}

	// Configure VPN based on type
	var config string
	var configFileName string
	var connectionInfo string

	// Log VPN type selection
	s.logger.WithField("vpn_type", req.VPNType).Info("Configuring VPN service")

	if req.VPNType == "ios" {
		config, configFileName, connectionInfo, err = s.configureStrongSwan(session, req.ServerIP, newPassword)
	} else if req.VPNType == "openvpn" {
		config, configFileName, connectionInfo, err = s.configureOpenVPN(session, req.ServerIP, newPassword)
	} else {
		return nil, fmt.Errorf("unsupported VPN type: %s", req.VPNType)
	}

	if err != nil {
		s.logger.WithError(err).Error("Failed to configure VPN")
		return nil, fmt.Errorf("failed to configure VPN: %w", err)
	}

	// Change user password with better error handling
	if _, stderr, err := session.ExecuteCommand(fmt.Sprintf("echo '%s:%s' | chpasswd", req.Username, newPassword)); err != nil {
		s.logger.WithError(err).WithField("stderr", stderr).Warn("Failed to change password")
		// Don't fail the whole operation if password change fails
	}

	// Cleanup and secure server
	if err := s.secureServer(session); err != nil {
		s.logger.WithError(err).Warn("Some security measures failed to apply")
		// Don't fail the whole operation if some security measures fail
	}

	s.logger.Info("VPN configuration completed successfully")

	return &ConfigResult{
		Config:         config,
		ConfigFileName: configFileName,
		NewPassword:    newPassword,
		ConnectionInfo: connectionInfo,
	}, nil
}

func (s *Service) findTemplateFile(filename string) ([]byte, error) {
	// Try different possible locations for the template file
	searchPaths := []string{
		filename, // Just the filename (for absolute paths)
		filepath.Join(s.configPath, "templates", filename),         // Config path (for tests)
		filepath.Join("backend", "configs", "templates", filename), // Project structure
		filepath.Join("configs", "templates", filename),            // Relative to working directory
	}

	var lastErr error
	for _, path := range searchPaths {
		content, err := os.ReadFile(path)
		if err == nil {
			return content, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("failed to find template %s in any location: %w", filename, lastErr)
}

// configureStrongSwan configures StrongSwan (IKEv2) VPN for iOS
func (s *Service) configureStrongSwan(session *ssh.Session, serverIP, password string) (string, string, string, error) {
	scriptContent, err := s.findTemplateFile("strongswan-setup.sh")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read StrongSwan setup script: %w", err)
	}

	// Generate VPN credentials
	vpnUsername := "vpnuser"
	vpnPassword, err := s.GeneratePassword(16)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate VPN password: %w", err)
	}

	// Update script with server IP and credentials
	script := string(scriptContent)
	replacements := map[string]string{
		"{{SERVER_IP}}":    serverIP,
		"{{VPN_USERNAME}}": vpnUsername,
		"{{VPN_PASSWORD}}": vpnPassword,
	}
	for key, value := range replacements {
		script = strings.ReplaceAll(script, key, value)
	}

	// Execute StrongSwan setup script
	stdout, stderr, err := session.ExecuteScript(script)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"stdout": stdout,
			"stderr": stderr,
		}).Error("Failed to configure StrongSwan")
		return "", "", "", fmt.Errorf("failed to configure StrongSwan: %v", err)
	}

	// Check if mobileconfig file was generated and download it
	mobileconfigPath := "/tmp/ios-vpn.mobileconfig"
	configFileContent, err := session.DownloadFile(mobileconfigPath)
	if err != nil {
		s.logger.WithError(err).Error("Failed to download iOS VPN configuration")
		return "", "", "", fmt.Errorf("failed to download iOS VPN configuration: %w", err)
	}

	// Validate config content
	config := string(configFileContent)
	if !strings.Contains(config, "PayloadContent") || !strings.Contains(config, serverIP) {
		s.logger.Error("Invalid StrongSwan configuration")
		return "", "", "", fmt.Errorf("invalid StrongSwan configuration: missing required fields")
	}

	// Clean up the remote mobileconfig file
	session.ExecuteCommand("rm -f " + mobileconfigPath)

	// Connection information for the user
	connectionInfo := fmt.Sprintf(`IKEv2/IPsec VPN Connection Information:
Server: %s
Username: %s
Password: %s`, serverIP, vpnUsername, vpnPassword)

	return config, "ios-vpn.mobileconfig", connectionInfo, nil
}

// configureOpenVPN configures OpenVPN server
func (s *Service) configureOpenVPN(session *ssh.Session, serverIP, password string) (string, string, string, error) {
	scriptContent, err := s.findTemplateFile("openvpn-setup.sh")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read OpenVPN setup script: %w", err)
	}

	// Generate client name
	clientName := "client"

	// Update script with server IP and client name
	script := string(scriptContent)
	replacements := map[string]string{
		"{{SERVER_IP}}":   serverIP,
		"{{CLIENT_NAME}}": clientName,
	}
	for key, value := range replacements {
		script = strings.ReplaceAll(script, key, value)
	}

	// Execute OpenVPN setup script
	stdout, stderr, err := session.ExecuteScript(script)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"stdout": stdout,
			"stderr": stderr,
		}).Error("Failed to configure OpenVPN")
		return "", "", "", fmt.Errorf("failed to configure OpenVPN: %v", err)
	}

	// Download the client configuration
	configPath := "/tmp/client.ovpn"
	configFileContent, err := session.DownloadFile(configPath)
	if err != nil {
		s.logger.WithError(err).Error("Failed to download OpenVPN configuration")
		return "", "", "", fmt.Errorf("failed to download OpenVPN configuration: %w", err)
	}

	// Validate config content
	config := string(configFileContent)
	if !strings.Contains(config, "remote") || !strings.Contains(config, serverIP) {
		s.logger.Error("Invalid OpenVPN configuration")
		return "", "", "", fmt.Errorf("invalid OpenVPN configuration: missing required fields")
	}

	// Clean up the remote client config file
	session.ExecuteCommand("rm -f " + configPath)

	// Connection information for the user
	connectionInfo := fmt.Sprintf(`OpenVPN Connection Information:
Import the .ovpn file into your OpenVPN client
Server: %s
Port: 1194/UDP
Protocol: UDP
Configuration file contains all necessary connection details`, serverIP)

	return config, "client.ovpn", connectionInfo, nil
}

// secureServer applies security measures to the remote server
func (s *Service) secureServer(session *ssh.Session) error {
	var errs []error

	// Install fail2ban with proper error handling
	if stdout, stderr, err := session.ExecuteCommand("apt-get update && apt-get install -y fail2ban"); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"stdout": stdout,
			"stderr": stderr,
		}).Warn("Failed to install fail2ban")
		errs = append(errs, fmt.Errorf("fail2ban installation failed: %w", err))
	}

	// Configure firewall with success logging
	firewallCommands := []string{
		"apt-get install -y ufw",
		"ufw allow 22/tcp",   // SSH
		"ufw allow 500/udp",  // IKEv2
		"ufw allow 4500/udp", // IKEv2 NAT traversal
		"ufw allow 1194/udp", // OpenVPN
		"echo 'y' | ufw enable",
	}

	for _, cmd := range firewallCommands {
		if stdout, stderr, err := session.ExecuteCommand(cmd); err != nil {
			s.logger.WithError(err).WithFields(logrus.Fields{
				"command": cmd,
				"stdout":  stdout,
				"stderr":  stderr,
			}).Warn("Firewall command failed")
			errs = append(errs, fmt.Errorf("firewall command failed: %s: %w", cmd, err))
		} else {
			s.logger.WithField("command", cmd).Debug("Firewall command succeeded")
		}
	}

	// Configure log rotation with proper error handling
	logrotateConfig := `
/var/log/openvpn/*.log /var/log/strongswan/*.log {
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        systemctl reload openvpn || true
        systemctl reload strongswan || true
    endscript
}
`
	if err := session.UploadFile([]byte(logrotateConfig), "/etc/logrotate.d/vpn"); err != nil {
		s.logger.WithError(err).Warn("Failed to configure log rotation")
		errs = append(errs, fmt.Errorf("log rotation configuration failed: %w", err))
	}

	// Disable root login via SSH with better error handling
	sshCommands := []string{
		"sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
		"systemctl restart sshd",
	}

	for _, cmd := range sshCommands {
		if stdout, stderr, err := session.ExecuteCommand(cmd); err != nil {
			s.logger.WithError(err).WithFields(logrus.Fields{
				"command": cmd,
				"stdout":  stdout,
				"stderr":  stderr,
			}).Warn("SSH security command failed")
			errs = append(errs, fmt.Errorf("SSH security command failed: %s: %w", cmd, err))
		}
	}

	// Clean up sensitive data
	cleanupCommands := []string{
		"rm -rf /root/.bash_history",
		"rm -rf /home/*/.bash_history",
		"history -c",
	}

	for _, cmd := range cleanupCommands {
		if _, _, err := session.ExecuteCommand(cmd); err != nil {
			s.logger.WithError(err).WithField("command", cmd).Debug("Cleanup command failed")
			// Don't add cleanup errors to errs slice as they are not critical
		}
	}

	if len(errs) > 0 {
		// Return combined error but don't fail the whole operation
		return fmt.Errorf("some security measures failed: %v", errs)
	}

	return nil
}

// GeneratePassword generates a secure random password (changed from generatePassword to make it public)
func (s *Service) GeneratePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	charsetLength := big.NewInt(int64(len(charset)))

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", err
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}
