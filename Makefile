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

# Run basic functionality test
test-basic: build
	./k6 run examples/basic-test.js

# Run custom format test
test-custom: build
	./k6 run examples/custom-test.js

# Test with your specific encrypted data
test-data: build
	./k6 run examples/test-your-data.js

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
	@echo "  test-basic    - Run basic functionality test"
	@echo "  test-custom   - Run custom format test"
	@echo "  test-data     - Test with your specific encrypted data"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Run Go linter"
	@echo "  init          - Initialize go modules"
	@echo "  build-all     - Build for all platforms"
	@echo "  help          - Show this help message"