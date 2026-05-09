# SSH Proxy — Design Document

> **Language:** Go · **Target:** Linux ELF binary  
> **Status:** Pre-implementation design  
> **Date:** 2026-05-09

---

## 1. System Overview

SSH Proxy คือ forward proxy ที่นั่งอยู่ระหว่าง SSH/SFTP client และ backend หลายตัว  
หน้าที่หลักคือ **authenticate client**, **route ตาม username regex**, แล้ว **dial ไปยัง backend** ที่ถูกต้องและ bridge session ทิศทางเดียว (transparent tunnel)

```
Client (SSH/SFTP)
       │
       │ TCP :22
       ▼
┌──────────────────┐
│   SSH Proxy      │  ← ไฟล์เดียว, stateless per-session
│  Rule Engine     │
│  Auth Handler    │
│  Backend Dialer  │
│  Channel Bridge  │
│  Metrics Server  │
└──────────────────┘
       │
       │ TCP (per-session dial)
   ┌───┴────────────────┐
   ▼                    ▼
Backend: nas        Backend: vm
192.168.2.10:22    192.168.2.30:2222
```

### ลักษณะสำคัญ

| ประเด็น | การตัดสินใจ |
|---|---|
| Concurrency model | Per-session goroutine pair (Go scheduler จัดการ) |
| Connection to backend | Per-session dial (สร้างใหม่ทุก session) |
| Config hot-reload | ไม่รองรับ — restart process |
| Config format | YAML |
| Observability | Structured JSON log + Prometheus `/metrics` |
| Backend connect timeout | 10 วินาที (hard cutoff) |

---

## 2. Architecture

### 2.1 Package Structure

```
ssh-proxy/
├── cmd/
│   └── proxy/
│       └── main.go               # Entrypoint, signal handling
├── internal/
│   ├── config/
│   │   ├── config.go             # Struct definitions, YAML loader
│   │   └── validate.go           # Validation ตอน startup
│   ├── proxy/
│   │   ├── server.go             # SSH ServerConfig setup, listener
│   │   ├── handler.go            # NewConn handler goroutine
│   │   └── bridge.go             # Bidirectional channel/request bridge
│   ├── router/
│   │   ├── router.go             # Rule matching (regex, priority order)
│   │   └── types.go              # MatchResult struct
│   ├── auth/
│   │   ├── auth.go               # Auth orchestrator (password / pubkey callbacks)
│   │   ├── password.go           # Forward password to backend, verify
│   │   └── pubkey.go             # Authorized keys check, key selection
│   ├── backend/
│   │   ├── dialer.go             # Dial backend SSH, key/password strategy
│   │   └── session.go            # Wrap *ssh.Client, track active sessions
│   ├── sftp/
│   │   └── tuning.go             # Window size, packet size constants
│   └── metrics/
│       └── metrics.go            # Prometheus collector definitions
├── config.example.yaml
├── Plans.md
├── go.mod
└── Makefile
```

### 2.2 Request Lifecycle

```
1. Client dials Proxy :22
2. TCP accept → NewConn goroutine
3. SSH handshake (proxy presents host key, negotiates algorithms)
4. Client auth attempt (password | publickey)
   4a. Proxy validates auth → MatchResult (backend, backend_username, rule flags)
   4b. ถ้า rule บังคับ pubkey_only และ client ใช้ password → reject
5. Auth success → NewChannel
6. Proxy dials Backend (TCP, 10s timeout)
7. Proxy authenticates to Backend (key strategy, ดู §4)
8. Proxy opens same channel type on Backend
9. Bridge goroutines: Client↔Backend (stdin/stdout/stderr + requests)
10. Either side closes → cleanup both
```

---

## 3. Configuration Schema (YAML)

```yaml
# ============================================================
# proxy — Listening endpoint & host keys
# ============================================================
proxy:
  listen: "0.0.0.0:22"
  host_keys:
    - /etc/ssh-proxy/host_ed25519
    - /etc/ssh-proxy/host_rsa        # RSA ≥ 2048 bit

  # SSH algorithm negotiation
  # ลำดับ = preference order (client เลือกจากรายการนี้)
  # รองรับ legacy ที่ยังปลอดภัย ไม่มี DES/arcfour/blowfish
  algorithms:
    kex:
      - curve25519-sha256
      - ecdh-sha2-nistp521
      - ecdh-sha2-nistp384
      - ecdh-sha2-nistp256
      - diffie-hellman-group14-sha256
      - diffie-hellman-group14-sha1       # legacy safe (no DES)
    ciphers:
      - chacha20-poly1305@openssh.com
      - aes256-gcm@openssh.com
      - aes128-gcm@openssh.com            # AES128-GCM (requested)
      - aes256-ctr
      - aes192-ctr
      - aes128-ctr
    macs:
      - hmac-sha2-512-etm@openssh.com
      - hmac-sha2-256-etm@openssh.com
      - hmac-sha2-512
      - hmac-sha2-256
      - hmac-sha1                         # legacy safe
    host_key_algos:
      - ssh-ed25519                       # Ed25519
      - ecdsa-sha2-nistp521
      - ecdsa-sha2-nistp384
      - ecdsa-sha2-nistp256               # ECDSA
      - rsa-sha2-512
      - rsa-sha2-256
      - ssh-rsa                           # RSA2048 legacy

# ============================================================
# proxy_credentials — Global fallback key ที่ Proxy ใช้ต่อ Backend
# ============================================================
proxy_credentials:
  private_key: /etc/ssh-proxy/proxy_id_rsa   # ใช้เมื่อ backend ไม่มี per-backend key

# ============================================================
# sftp — Buffer tuning สำหรับ SFTP / SCP
# ============================================================
sftp:
  # SSH channel window size (bytes) — ค่า default ของ Go คือ 64KB ซึ่งช้ามาก
  window_size: 67108864          # 64 MB
  # Max SSH packet payload size
  max_packet_size: 262144        # 256 KB
  # จำนวน in-flight SFTP request สูงสุด (read-ahead)
  max_concurrent_requests: 64

# ============================================================
# timeouts
# ============================================================
timeouts:
  backend_connect: 10s           # TCP dial + SSH handshake รวมกัน
  backend_handshake: 15s         # SSH handshake เฉพาะ (subset ของ connect)
  keepalive_interval: 30s        # SSH keepalive ไปยัง backend
  keepalive_count_max: 3         # ครั้งสูงสุดก่อน drop

# ============================================================
# backends — Target endpoint แต่ละตัว
# ============================================================
backends:
  nas:
    host: 192.168.2.10
    port: 22
    # Key ที่ Proxy ใช้ authenticate ไปยัง backend นี้ (priority สูงกว่า global)
    private_key: /etc/ssh-proxy/keys/nas_id_rsa
    # ถ้า key auth ล้มเหลว: fallback ใช้ password ที่ client ให้มา
    # (ใช้ได้เฉพาะกรณี client ใช้ password auth)
    fallback_to_password: true
    # ถ้า false: ปิด connection ทันทีเมื่อ key auth ล้มเหลว

  vm:
    host: 192.168.2.30
    port: 2222
    private_key: /etc/ssh-proxy/keys/vm_id_rsa
    fallback_to_password: false

  computer1:
    host: 192.168.2.50
    port: 22
    # ไม่มี private_key → fallback ไป global proxy_credentials.private_key
    fallback_to_password: true

# ============================================================
# rules — Routing rules (ประเมินตามลำดับ, first match wins)
# ============================================================
rules:
  # --- User-specific rules (ควรอยู่ก่อน เพราะ more specific) ---

  - name: "user1-vm-keyonly"
    # Regex บน incoming SSH username
    match: "^user1-vm$"
    backend: vm
    # backend_username: ชื่อ user ที่จะส่งให้ backend
    # รองรับ capture group ($1, $2, ...) จาก regex
    backend_username: "user1"
    # บังคับ pubkey auth เท่านั้น — reject ถ้า client ใช้ password
    require_pubkey: true

  - name: "admin-nas-keyonly"
    match: "^admin-nas$"
    backend: nas
    backend_username: "administrator"
    require_pubkey: true

  # --- Generic backend routing rules (ใช้ capture group) ---

  - name: "nas-wildcard"
    match: "^(.*)-nas$"
    backend: nas
    backend_username: "$1"          # capture group [1] = ส่วนหน้า dash

  - name: "vm-wildcard"
    match: "^(.*)-vm$"
    backend: vm
    backend_username: "$1"

  - name: "computer1-wildcard"
    match: "^(.*)-computer1$"
    backend: computer1
    backend_username: "$1"

# ============================================================
# metrics — Prometheus endpoint
# ============================================================
metrics:
  enabled: true
  listen: "0.0.0.0:9090"
  path: "/metrics"

# ============================================================
# logging
# ============================================================
logging:
  level: info                    # debug | info | warn | error
  format: json                   # json | text
  output: stdout                 # stdout | /var/log/ssh-proxy/proxy.log
```

---

## 4. Authentication Flow

### 4.1 Client → Proxy Authentication

```
Client เชื่อมต่อ
       │
       ├─[password auth]──────────────────────────────────────────┐
       │                                                           │
       └─[pubkey auth]─────────────────────────────────────────── │
                                                                   │
Proxy ประเมิน Rule (ตาม username):                                │
  ┌─ rule.require_pubkey == true?                                  │
  │     └─ client ใช้ password? → reject "publickey required"     │
  └─ ผ่าน → Auth success                                          │
                                                                   ▼
                                               MatchResult{backend, backend_username, ...}
```

**หมายเหตุ:** Proxy ไม่ verify password ต่อ local store — password ถูก verify ทาง backend (ดู §4.2)  
สำหรับ pubkey auth: Proxy ต้องมี `authorized_keys` per-user หรือ "accept all, verify ทาง backend" (configurable ใน future)

### 4.2 Proxy → Backend Authentication

```
                        ┌─── Client ใช้ password auth ───┐
                        │                                 │
                        │  Proxy ส่ง password เดิมของ    │
                        │  client ไปยัง backend           │
                        │  (password forwarding)          │
                        └─────────────────────────────────┘

                        ┌─── Client ใช้ pubkey auth ─────┐
                        │                                 │
                        │  1. Try: backend private_key    │◄── per-backend config
                        │     (ถ้าตั้งค่าไว้)             │
                        │         │                       │
                        │         ▼ fail?                 │
                        │  2. Try: global proxy key       │◄── proxy_credentials.private_key
                        │         │                       │
                        │         ▼ fail?                 │
                        │  3a. fallback_to_password=true  │
                        │      → ปิด connection           │
                        │      (ไม่มี password จาก client)│
                        │  3b. fallback_to_password=false │
                        │      → ปิด connection           │
                        └─────────────────────────────────┘
```

**สรุป key priority:**
1. Backend-specific private key (`backends.<name>.private_key`) — highest
2. Global proxy key (`proxy_credentials.private_key`) — fallback
3. Client password (forwarded) — เฉพาะกรณี client ใช้ password auth
4. ปิด connection

### 4.3 Per-User Rule (`require_pubkey`)

```
Client username: user1-vm
  │
  ├─ Match rule "user1-vm-keyonly" → require_pubkey: true
  │
  ├─ Client ใช้ password → SSH disconnect (publickey required)
  └─ Client ใช้ pubkey  → ผ่าน → ต่อ backend ด้วย vm private_key
```

---

## 5. Rule Engine

### 5.1 Matching Algorithm

```go
// Pseudo-code
func Match(username string, rules []Rule) (*MatchResult, error) {
    for _, rule := range rules {       // rules ตามลำดับใน config
        groups, ok := rule.Regex.FindStringSubmatch(username)
        if !ok {
            continue
        }
        backendUser := expandCaptures(rule.BackendUsername, groups)
        return &MatchResult{
            Rule:            rule,
            Backend:         cfg.Backends[rule.Backend],
            BackendUsername: backendUser,
        }, nil
    }
    return nil, ErrNoMatchingRule     // reject connection
}
```

### 5.2 Capture Group Expansion

| Pattern | Input username | `backend_username` config | Backend username |
|---|---|---|---|
| `^(.*)-nas$` | `john-nas` | `$1` | `john` |
| `^(.*)-vm$` | `alice-vm` | `$1` | `alice` |
| `^user1-vm$` | `user1-vm` | `user1` (literal) | `user1` |
| `^(.*)-nas$` | `bob.smith-nas` | `$1` | `bob.smith` |

### 5.3 Rule Ordering Best Practice

```yaml
rules:
  # 1. More specific rules FIRST (exact match)
  - name: "user1-vm-keyonly"
    match: "^user1-vm$"
    ...
  # 2. Wildcard rules LAST
  - name: "vm-wildcard"
    match: "^(.*)-vm$"
    ...
```

---

## 6. Channel Bridging (SFTP / SCP / Shell)

Proxy เป็น **transparent SSH proxy** — forward ทุก channel type และ request type โดยไม่ interpret:

```
Client Channel (shell/exec/subsystem/x11/...)
        │
        │ io.Copy goroutine pair
        ▼
Backend Channel (same type)
```

### 6.1 Channel Types ที่ต้อง Bridge

| Channel Type | ใช้สำหรับ |
|---|---|
| `session` | shell, exec, subsystem (sftp), env, pty |
| `direct-tcpip` | Local port forwarding |
| `forwarded-tcpip` | Remote port forwarding |

### 6.2 Request Types ที่ต้อง Forward

- `pty-req`, `shell`, `exec`, `subsystem`
- `window-change`, `signal`
- `env`

### 6.3 SFTP Buffer Tuning

SSH channel มี **flow control window** — ค่า default ของ Go SSH library คือ **64 KB** ซึ่งทำให้ SFTP ช้ามาก

```go
// internal/sftp/tuning.go
const (
    // SSH channel window — ต้องใหญ่พอสำหรับ in-flight data
    ChannelWindowSize = 64 * 1024 * 1024   // 64 MB

    // Max SSH packet payload
    ChannelMaxPacketSize = 256 * 1024       // 256 KB

    // SFTP read-ahead requests
    SFTPMaxConcurrentRequests = 64

    // SFTP buffer per request
    SFTPReadBufferSize  = 256 * 1024        // 256 KB
    SFTPWriteBufferSize = 256 * 1024        // 256 KB
)
```

**หมายเหตุ:** `golang.org/x/crypto/ssh` เปิดให้กำหนด `WindowSize` และ `MaxPacketSize` ใน `ssh.NewClientConn` และ `ssh.ServerConfig`. Library `github.com/pkg/sftp` รับ functional options ของ buffer size.

---

## 7. Supported SSH Algorithms

เป้าหมาย: รองรับ legacy ที่ยังปลอดภัย และต้องไม่มี DES/RC4/Blowfish  
ใช้รายการนี้ทั้งใน **Proxy listening side** และ **Backend dial side**

### 7.1 Key Exchange (KEX)

| Algorithm | Category | Notes |
|---|---|---|
| `curve25519-sha256` | Modern | RFC 8731 |
| `ecdh-sha2-nistp521` | Modern | |
| `ecdh-sha2-nistp384` | Modern | |
| `ecdh-sha2-nistp256` | Modern | |
| `diffie-hellman-group14-sha256` | Legacy-safe | Group 14 = 2048-bit |
| `diffie-hellman-group14-sha1` | Legacy-safe | SHA1 สำหรับ client เก่า |

ห้ามใช้: `diffie-hellman-group1-sha1` (1024-bit = Logjam)

### 7.2 Ciphers

| Algorithm | Category | Notes |
|---|---|---|
| `chacha20-poly1305@openssh.com` | Modern | Poly1305 MAC built-in |
| `aes256-gcm@openssh.com` | Modern | AES256-GCM |
| `aes128-gcm@openssh.com` | Modern | AES128-GCM (requested) |
| `aes256-ctr` | Standard | |
| `aes192-ctr` | Standard | |
| `aes128-ctr` | Standard | |

ห้ามใช้: `3des-cbc`, `arcfour*`, `blowfish-cbc`, `cast128-cbc`, `aes*-cbc` (CBC padding oracle)

### 7.3 MACs

| Algorithm | Notes |
|---|---|
| `hmac-sha2-512-etm@openssh.com` | ETM = Encrypt-then-MAC (preferred) |
| `hmac-sha2-256-etm@openssh.com` | |
| `hmac-sha2-512` | |
| `hmac-sha2-256` | |
| `hmac-sha1` | Legacy safe (SHA1 สำหรับ MAC ยังโอเค) |

ห้ามใช้: `hmac-md5*`, `hmac-sha1-96`

### 7.4 Host Key Algorithms

| Algorithm | Notes |
|---|---|
| `ssh-ed25519` | Ed25519 (requested) |
| `ecdsa-sha2-nistp521` | ECDSA |
| `ecdsa-sha2-nistp384` | ECDSA |
| `ecdsa-sha2-nistp256` | ECDSA (requested) |
| `rsa-sha2-512` | RSA + SHA512 |
| `rsa-sha2-256` | RSA + SHA256 |
| `ssh-rsa` | RSA2048 legacy (SHA1 signature) |

---

## 8. Performance Design

### 8.1 Concurrency Model

```
Listener goroutine
    │
    ├─ Accept() → handleConn goroutine  (1 per connection)
    │       │
    │       ├─ SSH handshake
    │       ├─ Auth
    │       ├─ Channel loop goroutine
    │       │       │
    │       │       └─ Per-channel:
    │       │               ├─ Bridge Read goroutine  (client→backend)
    │       │               └─ Bridge Write goroutine (backend→client)
    │       └─ Request loop goroutine
    │
    └─ (next connection)
```

**ประมาณการ goroutine:** 10,000 connections × ~6 goroutines = ~60,000 goroutines  
Go รองรับได้สบาย (stack เริ่มต้นที่ 2KB, grow on demand)

### 8.2 System Requirements สำหรับ 10,000 Concurrent

```bash
# /etc/security/limits.conf หรือ systemd LimitNOFILE
* soft nofile 131072
* hard nofile 131072

# /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
```

### 8.3 Runtime Tuning

```go
// main.go
import "runtime"

func main() {
    // Default คือ NumCPU() แล้ว — แต่ set ชัดเจน
    runtime.GOMAXPROCS(runtime.NumCPU())
    ...
}
```

### 8.4 Memory Estimate

| Component | ต่อ Connection | 10,000 Connections |
|---|---|---|
| SSH buffers | ~512 KB | ~5 GB |
| Goroutine stacks | ~12 KB × 6 | ~720 MB |
| Overhead | ~100 KB | ~1 GB |
| **รวม** | | **~7 GB RAM** |

แนะนำ: เครื่อง Proxy ควรมี RAM ≥ 16 GB สำหรับ 10,000 concurrent

---

## 9. Error Handling

### 9.1 Backend Connection Errors

| Scenario | Behavior |
|---|---|
| TCP dial timeout (>10s) | ส่ง SSH disconnect `SSH_DISCONNECT_BY_APPLICATION` ทันที |
| SSH handshake failure | Log + disconnect |
| Backend auth failure (key) | ตาม `fallback_to_password` config |
| Backend auth failure (password) | ใช้ retry ของ backend (proxy ไม่ได้ควบคุม) |
| No matching rule | Reject ทันที ก่อน complete auth |
| Backend disconnects mid-session | Close client session ทันที |

### 9.2 Client Auth Errors

| Scenario | Behavior |
|---|---|
| `require_pubkey=true` + password | Reject method, allow retry (SSH standard) |
| Unmatched username | ปิด connection หลัง auth phase |
| Multiple auth failures | ขึ้นกับ `MaxAuthTries` ใน ServerConfig (default 6) |

---

## 10. Metrics (Prometheus)

```
# Counters
ssh_proxy_connections_total{backend, auth_method, result}
ssh_proxy_auth_attempts_total{method, result, backend}
ssh_proxy_backend_dial_errors_total{backend, reason}
ssh_proxy_bytes_transferred_total{backend, direction}   # direction: "up"|"down"

# Gauges
ssh_proxy_connections_active{backend}
ssh_proxy_goroutines_total

# Histograms
ssh_proxy_connection_duration_seconds{backend}
ssh_proxy_backend_dial_duration_seconds{backend}
ssh_proxy_auth_duration_seconds{method}
```

HTTP endpoint: `GET http://0.0.0.0:9090/metrics`

---

## 11. Logging (JSON Structured)

ทุก log มี fields พื้นฐาน:

```json
{
  "ts": "2026-05-09T10:00:00.000Z",
  "level": "info",
  "msg": "session started",
  "client_ip": "10.0.0.1",
  "client_port": 54321,
  "username": "user1-vm",
  "backend_username": "user1",
  "backend": "vm",
  "backend_addr": "192.168.2.30:2222",
  "auth_method": "publickey",
  "rule": "user1-vm-keyonly",
  "session_id": "abc123"
}
```

Library แนะนำ: `go.uber.org/zap` (zero-alloc structured logging)

---

## 12. Go Dependencies

```
golang.org/x/crypto          v0.x   — SSH protocol (server + client)
github.com/pkg/sftp          v1.x   — SFTP subsystem (buffer options)
gopkg.in/yaml.v3             v3.x   — YAML config parser
github.com/prometheus/client_golang v1.x — Prometheus metrics
go.uber.org/zap              v1.x   — Structured JSON logging
```

---

## 13. Config File Paths (Recommended)

```
/etc/ssh-proxy/
├── config.yaml                  # Main config
├── host_ed25519                 # Proxy host key (Ed25519)
├── host_rsa                     # Proxy host key (RSA ≥ 2048)
├── proxy_id_rsa                 # Global proxy auth key
└── keys/
    ├── nas_id_rsa               # Per-backend key สำหรับ nas
    └── vm_id_rsa                # Per-backend key สำหรับ vm
```

---

## 14. Build

```makefile
# Makefile
BINARY = ssh-proxy

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -ldflags="-s -w" -o dist/$(BINARY) ./cmd/proxy

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	  go build -ldflags="-s -w" -o dist/$(BINARY)-arm64 ./cmd/proxy
```

```bash
make build-linux
# Output: dist/ssh-proxy  (ELF 64-bit, stripped)
```

---

## 15. Security Considerations

| ประเด็น | การจัดการ |
|---|---|
| Host key verification (proxy→backend) | ต้องตั้ง `HostKeyCallback` เป็น known_hosts หรือ hardcoded fingerprint — **ห้ามใช้ `InsecureIgnoreHostKey`** ใน production |
| Private key permissions | Enforce `chmod 600` ก่อน load — หากสิทธิ์ผิดให้ startup fail |
| Password in memory | ล้าง slice หลัง use (zero-fill) |
| Log sanitization | ห้าม log password หรือ private key content |
| Algorithm negotiation | ใช้ allowlist จาก §7 — ไม่ใช้ `ssh.Config{}` ค่า default ของ Go (ปลอดภัยอยู่แล้วแต่ควร explicit) |
| SYN flood | ใช้ OS TCP backlog + `net.ipv4.tcp_syncookies=1` |

---

## 16. Sequence Diagrams

### 16.1 Password Auth (client → proxy → backend)

```
Client          Proxy           Backend
  │                │                │
  │──TCP connect──►│                │
  │◄──host key─────│                │
  │──algo nego─────│                │
  │──password─────►│                │
  │                │──TCP dial──────►│ (10s timeout)
  │                │──SSH handshake─►│
  │                │──password fwd──►│
  │                │◄──auth success──│
  │◄──auth success─│                │
  │──open channel──►│               │
  │                │──open channel──►│
  │◄──────────────────── bridge ────►│
  │                │                │
```

### 16.2 Pubkey Auth (client → proxy → backend with per-backend key)

```
Client          Proxy           Backend
  │                │                │
  │──pubkey auth──►│                │
  │                │ match rule     │
  │                │ check require_pubkey ✓
  │◄──auth success─│                │
  │──open channel──►│               │
  │                │──TCP dial──────►│
  │                │──pubkey auth───►│ (ใช้ backends.vm.private_key)
  │                │◄──auth success──│
  │                │──open channel──►│
  │◄──────────────────── bridge ────►│
```

---

## 17. Open Items / Future Enhancements

> สิ่งเหล่านี้ไม่ได้อยู่ใน scope แรก แต่ควรออกแบบไม่ให้ขัดกับ architecture

- [ ] `authorized_keys` per-user บน Proxy (ตอนนี้ accept pubkey แล้ว verify ทาง backend)
- [ ] Backend health check (probe ก่อน route)
- [ ] Rate limiting ต่อ IP
- [ ] Admin REST API สำหรับ query active sessions
- [ ] TLS สำหรับ metrics endpoint
- [ ] Audit log แยก (session start/stop + bytes transferred)
- [ ] Config hot-reload (SIGHUP)
