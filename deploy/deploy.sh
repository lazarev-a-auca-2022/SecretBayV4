#!/bin/bash
# SecretBay Deployment Script

set -e

# Log function
log() {
    echo "[$(date)] $1"
}

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    log "This script must be run as root"
    exit 1
fi

# Configuration variables
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-secretbay}
JWT_SECRET=$(openssl rand -hex 32)
PORT=${PORT:-8443}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    log "Docker not found. Installing Docker..."
    
    # Update package lists
    apt-get update
    
    # Install prerequisites
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Set up the stable repository
    echo \
        "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker Engine
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io
    
    log "Docker installed successfully"
else
    log "Docker is already installed"
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    log "Docker Compose not found. Installing Docker Compose..."
    
    # Install Docker Compose
    curl -L "https://github.com/docker/compose/releases/download/v2.17.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    log "Docker Compose installed successfully"
else
    log "Docker Compose is already installed"
fi

# Create SecretBay directory
INSTALL_DIR="/opt/secretbay"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

log "Downloading SecretBay..."

# Clone the repository or download the release package
# For this example, we'll create the files directly
cat > docker-compose.yml << 'EOL'
version: '3.8'

services:
  secretbay:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: secretbay-server
    restart: unless-stopped
    ports:
      - "${PORT}:8443"
    volumes:
      - ./certs:/app/certs
      - ./logs:/app/logs
    environment:
      - TZ=UTC
      - ADMIN_USERNAME=${ADMIN_USERNAME}
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - JWT_SECRET=${JWT_SECRET}
    healthcheck:
      test: ["CMD", "wget", "--no-check-certificate", "--spider", "-q", "https://localhost:8443/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
EOL

# Create environment file
cat > .env << EOL
PORT=$PORT
ADMIN_USERNAME=$ADMIN_USERNAME
ADMIN_PASSWORD=$ADMIN_PASSWORD
JWT_SECRET=$JWT_SECRET
EOL

# Create directories
mkdir -p certs logs

# Check if Dockerfile exists
if [ ! -f Dockerfile ]; then
    log "Downloading Dockerfile..."
    curl -o Dockerfile https://raw.githubusercontent.com/yourusername/secretbay/main/Dockerfile
fi

# Check if image needs to be built
log "Building SecretBay Docker image..."
docker-compose build

# Start the service
log "Starting SecretBay service..."
docker-compose up -d

# Wait for service to start
log "Waiting for service to become available..."
for i in {1..30}; do
    if curl -k -s https://localhost:$PORT/api/health > /dev/null; then
        log "SecretBay service is up and running!"
        break
    fi
    
    if [ $i -eq 30 ]; then
        log "Timed out waiting for SecretBay service to start. Check logs with 'docker-compose logs'"
        exit 1
    fi
    
    log "Waiting for service to start... ($i/30)"
    sleep 2
done

# Print information
cat << EOL

------------------------------------------------------------
                SecretBay Installation Complete
------------------------------------------------------------

Access your SecretBay VPN Configuration Tool at:
    https://$(hostname -I | awk '{print $1}'):$PORT

Login credentials:
    Username: $ADMIN_USERNAME
    Password: $ADMIN_PASSWORD

You can modify these settings in $INSTALL_DIR/.env
and restart the service with:
    cd $INSTALL_DIR && docker-compose restart

------------------------------------------------------------
EOL

exit 0