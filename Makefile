BINARY = ssh-proxy

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -ldflags="-s -w" -o dist/$(BINARY) ./cmd/proxy

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	  go build -ldflags="-s -w" -o dist/$(BINARY)-arm64 ./cmd/proxy
