# email-watch Makefile

BINARY_NAME=email-watch
GO=go

.PHONY: all build test run clean fmt lint vet coverage help

# Default target
all: fmt vet test build

# Build the binary
build:
	$(GO) build -o $(BINARY_NAME) .

# Run tests
test:
	$(GO) test -v ./...

# Run tests with coverage
coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run the application (requires MSG_FILE argument)
run: build
	./$(BINARY_NAME) $(MSG_FILE)

# Format code
fmt:
	$(GO) fmt ./...

# Run go vet
vet:
	$(GO) vet ./...

# Run staticcheck if installed
lint:
	@which staticcheck > /dev/null || (echo "Installing staticcheck..." && go install honnef.co/go/tools/cmd/staticcheck@latest)
	staticcheck ./...

# Clean build artifacts
clean:
	$(GO) clean
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

# Download dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Build for multiple platforms
build-all: clean
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GO) build -o $(BINARY_NAME)-darwin-arm64 .
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-linux-amd64 .
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-windows-amd64.exe .

# Show help
help:
	@echo "email-watch Makefile targets:"
	@echo ""
	@echo "  make            - Format, vet, test, and build"
	@echo "  make build      - Build the binary"
	@echo "  make test       - Run tests with verbose output"
	@echo "  make coverage   - Run tests with coverage report"
	@echo "  make run MSG_FILE=<file.msg> - Build and run with a .msg file"
	@echo "  make fmt        - Format Go code"
	@echo "  make vet        - Run go vet"
	@echo "  make lint       - Run staticcheck linter"
	@echo "  make clean      - Remove build artifacts"
	@echo "  make deps       - Download and tidy dependencies"
	@echo "  make build-all  - Build for darwin, linux, and windows"
	@echo "  make help       - Show this help"
