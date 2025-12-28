# QDT (QUIC Datagram Tunnel)

Minimal VPN TUN prototype over HTTP/3 + QUIC datagrams. Linux-only MVP for now.

## Build

```
go build ./cmd/qdt-server
go build ./cmd/qdt-client
```

## Dev certificates

```
./scripts/gen-cert.sh cert.pem key.pem
```

## Server (Linux)

Run with root or CAP_NET_ADMIN to create the TUN device:

```
sudo ./qdt-server -addr :443 -cert cert.pem -key key.pem -token YOUR_TOKEN -tun qdt0 -mtu 1350
```

Configure the TUN interface in another shell (example subnet `10.8.0.0/24`):

```
sudo ip addr add 10.8.0.1/24 dev qdt0
sudo ip link set qdt0 up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
```

Replace `eth0` with your public interface.

## Client (Linux)

```
sudo ./qdt-client -server 135.181.7.44.sslip.io:443 -token YOUR_TOKEN -tun qdt0 -insecure
```

Then set up the client TUN address and route:

```
sudo ip addr add 10.8.0.2/24 dev qdt0
sudo ip link set qdt0 up
sudo ip route add default via 10.8.0.1 dev qdt0
```

To revert the route, delete it or bring the interface down.

## Notes

- This MVP supports a single active session at a time.
- Authentication is a static token via `X-QDT-Token`.
- No internal packet encryption yet (TLS-only). We'll add AEAD later if needed.

## Protocol (MVP)

Datagram layout (big-endian):

```
Magic[3] = \"QDT\"
Version[1]
Type[1] (0=Data, 1=Ping, 2=Pong, 3=Close)
Flags[1]
SessionID[8]
Counter[4]
Payload[...]
```
# qdt
