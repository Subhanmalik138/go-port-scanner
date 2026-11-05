// Package scanner probes TCP ports concurrently and reports what it finds.
//
// A Scanner dials each requested port with a per-port timeout, classifies it
// as open, closed or filtered, and — for open ports — tries to identify the
// service from the port number and from any banner the service volunteers
// on connect. Scanning is driven by a bounded worker pool so thousands of
// ports can be probed without opening thousands of sockets at once.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// State describes what a probe found.
type State int

const (
	// StateClosed means the target actively refused the connection.
	StateClosed State = iota
	// StateOpen means the TCP handshake completed.
	StateOpen
	// StateFiltered means no answer arrived before the timeout; a firewall
	// may be silently dropping packets, or the host may be down.
	StateFiltered
)

// String renders the state the way users expect to see it.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// Result is the outcome of probing one port.
type Result struct {
	Port    int
	State   State
	Service string
	Banner  string
	Latency time.Duration
}

// MarshalJSON renders a Result with a human-readable state string and the
// latency in whole milliseconds, instead of Go's default integer state
// and nanosecond duration.
func (r Result) MarshalJSON() ([]byte, error) {
	type resultJSON struct {
		Port      int    `json:"port"`
		State     string `json:"state"`
		Service   string `json:"service,omitempty"`
		Banner    string `json:"banner,omitempty"`
		LatencyMs int64  `json:"latency_ms"`
	}
	return json.Marshal(resultJSON{
		Port:      r.Port,
		State:     r.State.String(),
		Service:   r.Service,
		Banner:    r.Banner,
		LatencyMs: r.Latency.Milliseconds(),
	})
}

// Options tunes a Scanner.
type Options struct {
	// Timeout is the per-port dial (and banner-read) deadline.
	Timeout time.Duration
	// Workers caps how many ports are probed at the same time.
	Workers int
	// GrabBanner, when true, reads up to a few hundred bytes after connect
	// to identify the service. It adds one round trip per open port.
	GrabBanner bool
}

// DefaultOptions is a sensible starting point: 1s per port, 100 workers.
func DefaultOptions() Options {
	return Options{Timeout: time.Second, Workers: 100, GrabBanner: true}
}

// Scanner probes ports on a single host.
type Scanner struct {
	host string
	opts Options
}

// New returns a Scanner for host (name or IP) with the given options.
// Zero-valued option fields are replaced with the defaults.
func New(host string, opts Options) *Scanner {
	if opts.Timeout <= 0 {
		opts.Timeout = time.Second
	}
	if opts.Workers <= 0 {
		opts.Workers = 100
	}
	return &Scanner{host: host, opts: opts}
}

// Scan probes every port in ports and returns one Result per port, sorted
// by port number. It stops early if ctx is cancelled.
func (s *Scanner) Scan(ctx context.Context, ports []int) []Result {
	jobs := make(chan int)
	results := make(chan Result, len(ports))

	var wg sync.WaitGroup
	for i := 0; i < s.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				results <- s.probe(ctx, port)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return
			case jobs <- port:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]Result, 0, len(ports))
	for r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// probe dials a single port once and classifies the outcome.
func (s *Scanner) probe(ctx context.Context, port int) Result {
	res := Result{Port: port, Service: ServiceName(port)}
	start := time.Now()

	dialer := net.Dialer{Timeout: s.opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(s.host, fmt.Sprint(port)))
	res.Latency = time.Since(start)
	if err != nil {
		res.State = classifyDialError(err)
		return res
	}
	defer conn.Close()

	res.State = StateOpen
	if s.opts.GrabBanner {
		res.Banner = readBanner(conn, s.opts.Timeout)
		if svc := ServiceFromBanner(res.Banner); svc != "" {
			res.Service = svc
		}
	}
	return res
}

// classifyDialError maps a dial failure onto open/closed/filtered.
// A refused connection means the port is closed; anything else (timeout,
// unreachable network, DNS failure) is treated as filtered, since we
// cannot tell a silent firewall from a dead host.
func classifyDialError(err error) State {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return StateFiltered
	}
	// "connection refused" is the only error that proves the port is closed.
	if strings.Contains(err.Error(), "connection refused") {
		return StateClosed
	}
	return StateFiltered
}

// readBanner reads whatever the service sends first, up to 512 bytes,
// without waiting longer than timeout. Many services (SSH, SMTP, FTP)
// announce themselves immediately; HTTP and others stay quiet, which is
// fine — the returned string is simply empty.
func readBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}
