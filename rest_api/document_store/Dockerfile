# Stage 1: Build the Go application
FROM golang:1.26-bookworm AS builder

# Install system dependencies required for compilation
# libsofthsm2-dev is needed for PKCS#11 headers; gcc for CGO linking
RUN apt-get update && apt-get install -y \
    libsofthsm2-dev \
    opensc \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files and download modules for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Compile the binary
# CGO_ENABLED=1 is mandatory for PKCS#11/HSM support
RUN CGO_ENABLED=1 GOOS=linux go build -o main .

# Create a lightweight runtime image
FROM debian:bookworm-slim

# Install only the runtime libraries required for SoftHSM2
RUN apt-get update && apt-get install -y \
    libsofthsm2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/main .

# Expose the API port
EXPOSE 8080

# Launch the application
CMD ["./main"]