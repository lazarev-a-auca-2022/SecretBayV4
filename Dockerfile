# SecretBay Backend Dockerfile
FROM golang:1.20-alpine AS builder

# Set working directory
WORKDIR /app

# Install required packages
RUN apk add --no-cache git gcc musl-dev

# Copy and download dependencies
COPY go.mod ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o secretbay ./backend/cmd/server

# Create final lightweight image
FROM alpine:3.18

# Install required packages for runtime
RUN apk add --no-cache ca-certificates tzdata openssl

# Create app directories
RUN mkdir -p /app/logs /app/certs /app/configs /app/frontend

# Copy the binary from builder
COPY --from=builder /app/secretbay /app/
COPY --from=builder /app/backend/configs/templates /app/configs/templates
COPY --from=builder /app/frontend /app/frontend

# Set working directory
WORKDIR /app

# Expose the server port
EXPOSE 8443

# Run the application
ENTRYPOINT ["/app/secretbay"]