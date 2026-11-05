# go-port-scanner

A fast concurrent TCP port scanner in Go. It probes a host's ports with a bounded worker pool, classifies each port as open, closed or filtered, and identifies the service from the port number and from any banner the service volunteers on connect.

## Why this exists

Scanning is the textbook example of a problem that is embarrassingly parallel and I/O-bound: dialing ports one at a time is slow, dialing all of them at once exhausts file descriptors. The interesting design work is in the middle — a worker pool, per-port timeouts, and telling a refused connection (closed) apart from a silently dropped packet (filtered).

## Design decisions

- **Bounded worker pool over unbounded goroutines.** One goroutine per port would open thousands of sockets at once. A fixed pool of workers (default 100) pulling from a job channel keeps socket usage predictable while still scanning 1,000 ports in about a second on a LAN.
- **Closed vs. filtered is a real distinction.** A refused connection proves the port is closed; a timeout proves nothing except that nobody answered, so it is reported as filtered. Treating timeouts as "closed" is the most common bug in toy scanners.
- **Service identification is two-layered.** The port number gives the conventional service (22 → ssh); the connect banner refines it (an `SSH-2.0` banner confirms ssh even on a non-standard port). Banner grabbing is optional because it costs one round trip per open port.
- **Context cancellation throughout.** Ctrl-C cancels the scan cleanly via `signal.NotifyContext`, and a cancelled context stops workers instead of leaving them dialing.

## Usage

```bash
# Build
go build -o portscan ./cmd/portscan

# Scan the common well-known ports on a host
./portscan 192.168.1.1

# Scan specific ports, show only open ones
./portscan -ports 22,80,443 -open-only example.com

# Scan a range with a shorter timeout, JSON output
./portscan -ports 1-1024 -timeout 500 -json localhost
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-ports` | `common` | Ports to scan: `80,443`, `8000-8010`, or `common` |
| `-timeout` | `1000` | Per-port timeout in milliseconds |
| `-workers` | `100` | Number of concurrent probes |
| `-open-only` | `false` | Show only open ports |
| `-json` | `false` | Output results as JSON |
| `-no-banner` | `false` | Skip banner grabbing |

### Example output

```
Scanning 127.0.0.1 (30 ports) — 212ms

PORT     STATE      SERVICE        BANNER
----------------------------------------------------------------------
22       open       ssh            SSH-2.0-OpenSSH_9.6
80       closed     http
443      closed     https
3306     filtered   mysql

1 open / 30 scanned in 212ms
```

## How to run the tests

```bash
go test ./...
```

The tests cover port-spec parsing (single ports, ranges, lists, invalid input), service lookup, banner identification, and live scans against real local TCP servers — open ports with banners, refused (closed) ports, filtered ports via a non-routable address, and result ordering.

## Tech stack

- Go 1.23, standard library only — no external dependencies.
- `net.Dialer` with per-port deadlines for probing; `sync.WaitGroup` + channels for the worker pool.
