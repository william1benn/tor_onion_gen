FROM golang:1.21-alpine AS build

WORKDIR /app
COPY . .

RUN go mod download
RUN go build -o vanity_onion

FROM alpine:latest

RUN apk update && apk upgrade

WORKDIR /app
COPY --from=build /app/vanity_onion .

CMD ["./vanity_onion"]