FROM golang:alpine as base

# Install libpcap headers and the compilation tools needed
RUN apk add --update --no-cache ca-certificates libpcap-dev build-base

WORKDIR /app

ENV GO111MODULE=on \
    CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -ldflags="-s -w -extldflags '-static'" -o /app/melody ./cmd/melody

# Copy only what's needed
FROM scratch
COPY --from=base /app /app
WORKDIR /app

ENTRYPOINT ["/app/melody"]
