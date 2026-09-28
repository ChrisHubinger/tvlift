BINARY  := tvlift
VERSION ?= 1.0.0
DIST    := dist
LDFLAGS := -s -w -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all build run status test vet fmt lint dist docker up down logs clean help

all: lint test build

build:
	$(GOBUILD) -o $(BINARY) .

run: build
	set -a; [ -f .env ] && . ./.env; set +a; ./$(BINARY) serve

status: build
	set -a; [ -f .env ] && . ./.env; set +a; ./$(BINARY) status

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

dist:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64         $(GOBUILD) -o $(DIST)/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64         $(GOBUILD) -o $(DIST)/$(BINARY)-linux-arm64 .
	GOOS=linux GOARCH=arm GOARM=7   $(GOBUILD) -o $(DIST)/$(BINARY)-linux-armv7 .

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) -t $(BINARY):latest .

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

clean:
	rm -f $(BINARY)
	rm -rf $(DIST)

help:
	@echo "Targets: build run status test vet fmt lint dist docker up down logs clean"
	@echo "Override version: make dist VERSION=1.2.3"
