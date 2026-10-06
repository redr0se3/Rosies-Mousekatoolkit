BINARY := recontool
PKG    := ./cmd/recontool
DIST   := dist

.PHONY: build build-arm64 build-all vet test clean

build:
	go build -o $(BINARY) $(PKG)

# Pure-Go, no cgo — this is what makes cross-compiling to another CPU
# architecture a one-line GOARCH flag instead of needing a cross
# toolchain or a different build machine.
build-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -o $(DIST)/$(BINARY)-linux-arm64  $(PKG)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(DIST)/$(BINARY)-darwin-arm64 $(PKG)

build-all: build-arm64
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o $(DIST)/$(BINARY)-linux-amd64  $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -o $(DIST)/$(BINARY)-darwin-amd64 $(PKG)

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -rf $(BINARY) $(DIST)
