FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/qdt-server ./cmd/qdt-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y iproute2 iptables ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/qdt-server /usr/local/bin/qdt-server
ENTRYPOINT ["/usr/local/bin/qdt-server"]
