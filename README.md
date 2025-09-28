# dns-exfil (A & DoH)

Minimal DNS exfiltration PoC in Go.

- **Clients**
  - `exfil_dns_a.go`: encodes a file in Base32 (no padding) and sends it via **A-record** lookups like
    `SEQ.<chunk>.<session>.<domain>`.
  - `exfil_doh.go`: same idea, but over **DNS-over-HTTPS (DoH)**.
- **Server**
  - `server.go`: simple authoritative DNS server that collects chunks per `session`, reconstructs the payload, and writes it to `received/`.

---

## ⚠️ Disclaimer

This project is for **authorized security testing and research only**.
Use it **only on assets you own or have explicit written permission to test**.
You are solely responsible for compliance with laws, policies, and contracts.

---

## Build

```bash
# init module once (in repo root)
go mod init example.com/dns-exfil
go get github.com/miekg/dns

# build binaries
go build -o exfil_dns_a ./exfil_dns_a.go
go build -o exfil_doh   ./exfil_doh.go
go build -o exfil_server ./server.go
