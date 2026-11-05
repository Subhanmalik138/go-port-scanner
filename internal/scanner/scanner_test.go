package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		spec string
		want []int
	}{
		{"80", []int{80}},
		{"80,443,8080", []int{80, 443, 8080}},
		{"8000-8002", []int{8000, 8001, 8002}},
		{"80,8000-8002,443", []int{80, 443, 8000, 8001, 8002}},
		{"443,80,443", []int{80, 443}}, // duplicates removed
		{" 80 , 443 ", []int{80, 443}}, // whitespace tolerated
	}
	for _, tc := range cases {
		got, err := ParsePortSpec(tc.spec)
		if err != nil {
			t.Fatalf("ParsePortSpec(%q): unexpected error: %v", tc.spec, err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParsePortSpec(%q) = %v, want %v", tc.spec, got, tc.want)
		}
	}
}

func TestParsePortSpecErrors(t *testing.T) {
	for _, spec := range []string{"", "0", "65536", "abc", "80-", "-80", "9000-8000", "80,,443", "80-"} {
		if _, err := ParsePortSpec(spec); err == nil {
			t.Errorf("ParsePortSpec(%q): expected error, got nil", spec)
		}
	}
}

func TestParsePortSpecCommon(t *testing.T) {
	ports, err := ParsePortSpec("common")
	if err != nil {
		t.Fatalf("ParsePortSpec(common): %v", err)
	}
	if len(ports) < 10 {
		t.Errorf("common preset returned only %d ports", len(ports))
	}
	for _, p := range []int{22, 80, 443, 3306} {
		found := false
		for _, got := range ports {
			if got == p {
				found = true
			}
		}
		if !found {
			t.Errorf("common preset missing port %d", p)
		}
	}
}

func TestServiceName(t *testing.T) {
	if got := ServiceName(22); got != "ssh" {
		t.Errorf("ServiceName(22) = %q, want ssh", got)
	}
	if got := ServiceName(5432); got != "postgres" {
		t.Errorf("ServiceName(5432) = %q, want postgres", got)
	}
	if got := ServiceName(12345); got != "unknown" {
		t.Errorf("ServiceName(12345) = %q, want unknown", got)
	}
}

func TestServiceFromBanner(t *testing.T) {
	cases := []struct {
		banner string
		want   string
	}{
		{"SSH-2.0-OpenSSH_9.6", "ssh"},
		{"220 mail.example.com ESMTP", "smtp"},
		{"+OK Dovecot ready.", "pop3"},
		{"* OK IMAP ready", "imap"},
		{"-ERR unknown command", "redis"},
		{"", ""},
		{"HTTP/1.1 400 Bad Request", ""}, // HTTP stays quiet on connect
	}
	for _, tc := range cases {
		if got := ServiceFromBanner(tc.banner); got != tc.want {
			t.Errorf("ServiceFromBanner(%q) = %q, want %q", tc.banner, got, tc.want)
		}
	}
}

// startTestServer listens on a random localhost port and, for every
// connection, writes banner and then closes. It returns the port.
func startTestServer(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fmt.Fprint(c, banner)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestScanOpenPortWithBanner(t *testing.T) {
	port := startTestServer(t, "SSH-2.0-OpenSSH_9.6\r\n")
	s := New("127.0.0.1", Options{Timeout: 2 * time.Second, Workers: 4, GrabBanner: true})
	results := s.Scan(context.Background(), []int{port})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.State != StateOpen {
		t.Errorf("state = %v, want open", r.State)
	}
	if r.Service != "ssh" {
		t.Errorf("service = %q, want ssh (from banner)", r.Service)
	}
	if r.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("banner = %q, want SSH banner", r.Banner)
	}
}

func TestScanClosedPort(t *testing.T) {
	// Grab a port, then close the listener so the port is free (and
	// therefore refused) at scan time.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	s := New("127.0.0.1", Options{Timeout: 2 * time.Second, Workers: 4})
	results := s.Scan(context.Background(), []int{port})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].State != StateClosed {
		t.Errorf("state = %v, want closed", results[0].State)
	}
}

func TestScanFilteredPort(t *testing.T) {
	// 10.255.255.1 is a non-routable address in this sandbox: packets are
	// dropped, so the dial times out and the port reads as filtered.
	s := New("10.255.255.1", Options{Timeout: 200 * time.Millisecond, Workers: 2})
	results := s.Scan(context.Background(), []int{80})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].State != StateFiltered {
		t.Errorf("state = %v, want filtered", results[0].State)
	}
}

func TestScanResultsSorted(t *testing.T) {
	p1 := startTestServer(t, "SSH-2.0-test\r\n")
	p2 := startTestServer(t, "SSH-2.0-test\r\n")
	s := New("127.0.0.1", Options{Timeout: 2 * time.Second, Workers: 2})
	ports := []int{p2, p1} // deliberately unsorted input
	results := s.Scan(context.Background(), ports)
	if len(results) != 2 || results[0].Port > results[1].Port {
		t.Errorf("results not sorted by port: %+v", results)
	}
	for _, r := range results {
		if r.State != StateOpen {
			t.Errorf("port %d: state = %v, want open", r.Port, r.State)
		}
	}
}

func TestStateString(t *testing.T) {
	if StateOpen.String() != "open" || StateClosed.String() != "closed" || StateFiltered.String() != "filtered" {
		t.Errorf("unexpected State strings: %q %q %q", StateOpen, StateClosed, StateFiltered)
	}
}

func TestResultJSON(t *testing.T) {
	r := Result{Port: 22, State: StateOpen, Service: "ssh", Banner: "SSH-2.0-test", Latency: 3 * time.Millisecond}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(data)
	for _, want := range []string{`"port":22`, `"state":"open"`, `"service":"ssh"`, `"banner":"SSH-2.0-test"`, `"latency_ms":3`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON %s missing %s", got, want)
		}
	}
}
