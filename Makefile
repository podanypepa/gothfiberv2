.DEFAULT_GOAL := lint

## lint: checke all sources for errors
lint:
	@printf "\nLINTING\n"
	wrapcheck ./...
	golint ./...
	errcheck ./...
	golangci-lint run ./...
	gosec ./...

.PHONY: help

all: help

help: Makefile
	@echo
	@echo " Choose a command run in:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo
