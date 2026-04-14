FROM golang:1.25-alpine
WORKDIR /test
COPY test_exploit.go .
# Initialize a fresh module and resolve dependencies in the container.
# This avoids needing go.sum/go.mod from the host, which is brittle
# when the LLM-generated test imports third-party packages.
RUN go mod init openant-test 2>/dev/null || true
RUN go mod tidy
RUN go build -o test_exploit test_exploit.go
CMD ["./test_exploit"]
