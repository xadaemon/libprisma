PATH:=$(PATH):$(shell go env GOPATH)/bin
CGO_ENABLED:=1

test: *.go
	go test -v ./...
	
