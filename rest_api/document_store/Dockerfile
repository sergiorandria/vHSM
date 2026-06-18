# Stage 1: Build the Go application
FROM golang:1.26-bookworm AS builder

# Install system dependencies required for compilation
RUN apt-get update && apt-get install -y \
    libsofthsm2-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files and download modules for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Compile the binary with CGO enabled
RUN CGO_ENABLED=1 GOOS=linux go build -o main .


# Stage 2: Create a lightweight runtime image
FROM debian:bookworm-slim

# Install the runtime libraries AND tools needed for initialization
RUN apt-get update && apt-get install -y \
    libsofthsm2 \
    softhsm2 \
    opensc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/main .

# Copy the initialization script from the host into the final image
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose the API port
EXPOSE 8080

# Set the script as the container's entrypoint
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]