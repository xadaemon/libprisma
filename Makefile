PATH:=$(PATH):$(shell go env GOPATH)/bin

test: cryptography/*.go
	go test -v ./...
