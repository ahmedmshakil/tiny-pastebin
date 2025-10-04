# syntax=docker/dockerfile:1

FROM golang:1.22 AS build
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o tinypaste ./cmd/tinypaste

FROM gcr.io/distroless/static-debian12
WORKDIR /
COPY --from=build /app/tinypaste /tinypaste
EXPOSE 8080
ENTRYPOINT ["/tinypaste"]
