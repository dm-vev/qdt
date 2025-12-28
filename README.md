# QDT (QUIC Datagram Tunnel)

Production-focused VPN TUN over HTTP/3 + QUIC datagrams with PSK token auth, AEAD, fragmentation, and multi-session routing. Linux server, Linux/Windows clients.

## Build

```
go build ./cmd/qdt-server
go build ./cmd/qdt-client
```

## Dev certificates

```
./scripts/gen-cert.sh cert.pem key.pem
```

## Server config (server.yaml)

```
addr: ":443"
tls_cert: "/etc/qdt/cert.pem"
tls_key: "/etc/qdt/key.pem"
token: "YOUR_TOKEN"
mtu: 1350
tun_name: "qdt0"
pool_cidr: "10.8.0.0/24"
gateway_ip: "10.8.0.1"
dns: ["1.1.1.1", "8.8.8.8"]
metrics_addr: ":9100"
health_addr: ":9200"
log_level: "info"
log_json: false
session_timeout: 2m
rate_limit:
  pps: 10000
  burst: 20000
send_workers: 8
send_queue: 4096
send_batch: 4
session_shards: 64
nat:
  enabled: true
  external_iface: "eth0"
```

Run (Linux, requires CAP_NET_ADMIN):

```
sudo ./qdt-server -config server.yaml
```

## Client config (client.yaml)

```
server: "135.181.7.44.sslip.io:443"
token: "YOUR_TOKEN"
mtu: 1350
tun_name: "qdt0"
route_mode: "default" # default|cidr|none
dns: []
log_level: "info"
log_json: false
insecure: true
client_id: "laptop"
```

Run:

```
sudo ./qdt-client -config client.yaml
```

## Metrics and health

- `http://<server>:9100/metrics`
- `http://<server>:9100/healthz`

## Docker

```
docker compose up --build
```

The container needs:

- `--cap-add=NET_ADMIN`
- `/dev/net/tun` device
- host networking for UDP/443

## Protocol (v1)

Handshake:

- Client sends JSON body to `POST /connect` with `client_nonce`, `mtu`, `caps` and token header.
- Server responds with JSON `session_id`, `server_nonce`, `client_ip`, `gateway_ip`, `cidr`, `mtu`.
- Both sides derive keys via HKDF-SHA256 using token + nonces.

Datagram layout (big-endian):

```
Magic[3] = "QDT"
Version[1]
Type[1] (0=Data, 1=Fragment, 2=Ping, 3=Pong, 4=Close)
Flags[1]
SessionID[8]
Counter[8]
Ciphertext[...]
```

- Payload is AEAD-encrypted with AAD = header.
- Fragment payload layout: `ID[4] | Offset[4] | Total[4] | Data[...]`.

## Notes

- QDT uses UDP/443 directly. Caddy can stay on TCP/443.
- Token is a PSK; rotate and protect it.
- Windows clients require Wintun driver installed.
