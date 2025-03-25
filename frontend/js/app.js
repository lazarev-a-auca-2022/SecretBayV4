// SecretBay Frontend Application
document.addEventListener('DOMContentLoaded', function() {
    // Variables for storing application state
    let authToken = null;
    let configData = null;
    let configBlob = null;
    
    // DOM elements
    const loginSection = document.getElementById('login-section');
    const configSection = document.getElementById('config-section');
    const progressSection = document.getElementById('progress-section');
    const resultSection = document.getElementById('result-section');
    const errorSection = document.getElementById('error-section');
    
    const loginForm = document.getElementById('login-form');
    const configForm = document.getElementById('config-form');
    const authMethod = document.getElementById('auth-method');
    const passwordGroup = document.getElementById('password-group');
    const keyGroup = document.getElementById('key-group');
    const progressBar = document.getElementById('progress');
    const progressStatus = document.getElementById('progress-status');
    const downloadConfig = document.getElementById('download-config');
    const newPassword = document.getElementById('new-password');
    const connectionInfo = document.getElementById('connection-info');
    const errorMessage = document.getElementById('error-message');
    const configureNew = document.getElementById('configure-new');
    const tryAgain = document.getElementById('try-again');
    
    // Helper functions
    function showSection(section) {
        [loginSection, configSection, progressSection, resultSection, errorSection].forEach(s => {
            s.classList.add('hidden');
        });
        section.classList.remove('hidden');
    }
    
    function updateProgress(percent, message) {
        progressBar.style.width = `${percent}%`;
        progressStatus.textContent = message;
    }
    
    // Authentication method change handler
    authMethod.addEventListener('change', function() {
        if (this.value === 'password') {
            passwordGroup.classList.remove('hidden');
            keyGroup.classList.add('hidden');
        } else {
            passwordGroup.classList.add('hidden');
            keyGroup.classList.remove('hidden');
        }
    });
    
    // Login form submission
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        // Simple client-side validation
        if (!username || !password) {
            alert('Please enter both username and password');
            return;
        }
        
        // Authenticate with the server
        updateProgress(10, 'Authenticating...');
        showSection(progressSection);
        
        fetch('/api/authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Authentication failed. Please check your credentials.');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                authToken = data.data.token;
                updateProgress(100, 'Authentication successful!');
                setTimeout(() => {
                    showSection(configSection);
                }, 1000);
            } else {
                throw new Error(data.message || 'Authentication failed');
            }
        })
        .catch(error => {
            errorMessage.textContent = error.message;
            showSection(errorSection);
        });
    });
    
    // VPN Configuration form submission
    configForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const serverIP = document.getElementById('server-ip').value;
        const username = document.getElementById('server-username').value;
        const authMethod = document.getElementById('auth-method').value;
        const vpnType = document.getElementById('vpn-type').value;
        
        let authCredential = '';
        if (authMethod === 'password') {
            authCredential = document.getElementById('server-password').value;
        } else {
            authCredential = document.getElementById('ssh-key').value;
        }
        
        // Validate form
        if (!serverIP || !username || !authCredential || !vpnType) {
            alert('Please fill in all required fields');
            return;
        }
        
        // Show progress UI
        showSection(progressSection);
        updateProgress(10, 'Connecting to server...');
        
        // Configure VPN
        fetch('/api/configure', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': authToken
            },
            body: JSON.stringify({
                server_ip: serverIP,
                username: username,
                auth_method: authMethod,
                auth_credential: authCredential,
                vpn_type: vpnType
            })
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || 'Failed to configure VPN');
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Store config data for download
                configData = data.data;
                
                // Create blob for download
                const fileContent = configData.config;
                const fileName = configData.config_file_name;
                
                // Create a blob of the file
                configBlob = new Blob([fileContent], { type: 'text/plain' });
                
                // Update download link
                downloadConfig.setAttribute('download', fileName);
                downloadConfig.href = URL.createObjectURL(configBlob);
                
                // Update result UI
                newPassword.textContent = configData.new_password;
                connectionInfo.textContent = configData.connection_info;
                
                // Show result
                updateProgress(100, 'VPN configuration complete!');
                setTimeout(() => {
                    showSection(resultSection);
                }, 1000);
            } else {
                throw new Error(data.message || 'Failed to configure VPN');
            }
        })
        .catch(error => {
            errorMessage.textContent = error.message;
            showSection(errorSection);
        });
    });
    
    // Event listeners for action buttons
    configureNew.addEventListener('click', function() {
        configForm.reset();
        showSection(configSection);
    });
    
    tryAgain.addEventListener('click', function() {
        showSection(configSection);
    });
    
    // Simulated progress updates for better UX
    function simulateProgress() {
        const stages = [
            { percent: 20, message: 'Connecting to server...' },
            { percent: 30, message: 'Installing required packages...' },
            { percent: 40, message: 'Configuring VPN server...' },
            { percent: 60, message: 'Setting up security...' },
            { percent: 80, message: 'Generating client configurations...' },
            { percent: 90, message: 'Finalizing setup...' }
        ];
        
        let currentStage = 0;
        
        const interval = setInterval(() => {
            if (progressSection.classList.contains('hidden')) {
                clearInterval(interval);
                return;
            }
            
            if (currentStage < stages.length) {
                updateProgress(stages[currentStage].percent, stages[currentStage].message);
                currentStage++;
            } else {
                clearInterval(interval);
            }
        }, 3000);
    }
    
    // Start simulated progress when configForm is submitted
    configForm.addEventListener('submit', simulateProgress);
});