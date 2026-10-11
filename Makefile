.PHONY: all build test bench vet clean run

BINARY_NAME=bin/aegis.exe

all: vet test build

build:
	go build -o $(BINARY_NAME) ./cmd/aegis

test:
	go test -v ./...

bench:
	go test -v -bench="." -run="^$$" ./...

vet:
	go vet ./...

run:
	go run ./cmd/aegis -config config/aegis.json

clean:
	@if exist bin rmdir /s /q bin
