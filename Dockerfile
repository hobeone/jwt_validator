# Dockerfile

# --- Build Stage ---
# Use the official Go image as a builder
FROM golang:1.24.5-bookworm AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go application.
# -ldflags="-w -s" strips debugging information, reducing the binary size.
# CGO_ENABLED=0 creates a static binary.
RUN CGO_ENABLED=0 GOOS=linux go build -v -o jwt-validator -ldflags="-w -s" .

# --- Final Stage ---
# Use a minimal base image for the final container
FROM alpine:latest

# Set the working directory
WORKDIR /root/

# Copy only the compiled binary from the builder stage
COPY --from=builder /app/jwt-validator .

# Expose the port the service will run on
EXPOSE 9001

# Command to run the application
CMD ["./jwt-validator"]
