# Build Stage
FROM golang:alpine as build

WORKDIR /dnsscrew/

COPY ipLists.go .
COPY thxchatgpt.go .
COPY main.go .

COPY go.mod .
COPY go.sum .

RUN go mod download

RUN go build -o /app/dnsScrew

# Final Stage
FROM alpine:latest
WORKDIR /app
COPY --from=build /app/dnsScrew /app/
COPY cloudfront.json .

EXPOSE 52
ENV UPSTREAM_DNS_SERVER=2620:fe::fe

CMD ./dnsScrew
