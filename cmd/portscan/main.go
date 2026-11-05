// Command portscan is a fast concurrent TCP port scanner.
//
// Usage:
//
//	portscan [flags] <host>
//
//	  -ports string    ports to scan: "80,443", "8000-8010", "common" (default "common")
//	  -timeout int     per-port timeout in milliseconds (default 1000)
//	  -workers int     concurrent probes (default 100)
//	  -open-only       show only open ports
//	  -json            output results as JSON
//	  -no-banner       skip banner grabbing
//
// Examples:
//
//	portscan 192.168.1.1
//	portscan -ports 22,80,443 -open-only example.com
//	portscan -ports 1-1024 -timeout 500 -json localhost
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Subhanmalik138/go-port-scanner/internal/scanner"
)

func main() {
	portsFlag := flag.String("ports", "common", "ports to scan: \"80,443\", \"8000-8010\", or \"common\"")
	timeoutFlag := flag.Int("timeout", 1000, "per-port timeout in milliseconds")
	workersFlag := flag.Int("workers", 100, "number of concurrent probes")
	openOnlyFlag := flag.Bool("open-only", false, "show only open ports")
	jsonFlag := flag.Bool("json", false, "output results as JSON")
	noBannerFlag := flag.Bool("no-banner", false, "skip banner grabbing")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: portscan [flags] <host>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	host := flag.Arg(0)

	ports, err := scanner.ParsePortSpec(*portsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portscan: %v\n", err)
		os.Exit(2)
	}
	if *timeoutFlag <= 0 || *workersFlag <= 0 {
		fmt.Fprintln(os.Stderr, "portscan: --timeout and --workers must be positive")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	s := scanner.New(host, scanner.Options{
		Timeout:    time.Duration(*timeoutFlag) * time.Millisecond,
		Workers:    *workersFlag,
		GrabBanner: !*noBannerFlag,
	})

	start := time.Now()
	results := s.Scan(ctx, ports)
	elapsed := time.Since(start)

	open := 0
	for _, r := range results {
		if r.State == scanner.StateOpen {
			open++
		}
	}

	if *jsonFlag {
		out := struct {
			Host    string           `json:"host"`
			Open    int              `json:"open"`
			Scanned int              `json:"scanned"`
			Elapsed string           `json:"elapsed"`
			Results []scanner.Result `json:"results"`
		}{Host: host, Open: open, Scanned: len(results), Elapsed: elapsed.String(), Results: results}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "portscan: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("Scanning %s (%d ports) — %s\n\n", host, len(ports), elapsed.Round(time.Millisecond))
	fmt.Printf("%-8s %-10s %-14s %s\n", "PORT", "STATE", "SERVICE", "BANNER")
	fmt.Println(strings.Repeat("-", 70))
	for _, r := range results {
		if *openOnlyFlag && r.State != scanner.StateOpen {
			continue
		}
		fmt.Printf("%-8d %-10s %-14s %s\n", r.Port, r.State, r.Service, truncate(r.Banner, 40))
	}
	fmt.Printf("\n%d open / %d scanned in %s\n", open, len(results), elapsed.Round(time.Millisecond))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
