FROM golang:alpine as base

RUN apk --update add --no-cache ca-certificates libpcap-dev build-base

WORKDIR /app

ENV GO111MODULE=on \
    CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

# it will take the flags from the environment
RUN go build -ldflags="-s -w" -o melody
#RUN setcap cap_net_raw,cap_setpcap=ep ./melody

ENTRYPOINT ["/app/melody"]
#ENTRYPOINT ["/bin/ash", "-c", "sleep 100000000"]
