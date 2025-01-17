PATH:=$(PATH):$(shell go env GOPATH)/bin
CGO_ENABLED:=1

tool:
	go build \
    	-ldflags="-w -s" \
    	-o ./bin/ ./...

proto:
	protoc --go_out=. --go_opt=paths=source_relative --experimental_allow_proto3_optional protoutils/*.proto