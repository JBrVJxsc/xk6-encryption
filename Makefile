.PHONY: build clean test install-xk6

# Build the k6 binary with encryption extension
build:
	xk6 build --with github.com/JBrVJxsc/xk6-encryption=.

# Install xk6 if not already installed
install-xk6:
	go install go.k6.io/xk6/cmd/xk6@latest

# Clean build artifacts
clean:
	rm -f k6

# Test the extension
test:
	go test -v ./...

# Run a sample test with the built k6 binary
test-sample: build
	./k6 run examples/basic-test.js

# Format Go code
fmt:
	go fmt ./...

# Run Go linter
lint:
	golangci-lint run

# Initialize go modules
init:
	go mod init github.com/JBrVJxsc/xk6-encryption
	go mod tidy

# Build for different platforms
build-all: build-linux build-windows build-darwin

build-linux:
	GOOS=linux GOARCH=amd64 xk6 build --with github.com/JBrVJxsc/xk6-encryption=. --output k6-linux-amd64

build-windows:
	GOOS=windows GOARCH=amd64 xk6 build --with github.com/JBrVJxsc/xk6-encryption=. --output k6-windows-amd64.exe

build-darwin:
	GOOS=darwin GOARCH=amd64 xk6 build --with github.com/JBrVJxsc/xk6-encryption=. --output k6-darwin-amd64

# Help target
help:
	@echo "Available targets:"
	@echo "  build         - Build k6 with encryption extension"
	@echo "  install-xk6   - Install xk6 tool"
	@echo "  clean         - Remove build artifacts"
	@echo "  test          - Run Go tests"
	@echo "  test-sample   - Run sample k6 test"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Run Go linter"
	@echo "  init          - Initialize go modules"
	@echo "  build-all     - Build for all platforms"
	@echo "  help          - Show this help message"