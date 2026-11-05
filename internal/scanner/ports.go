package scanner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// wellKnownPorts is the set of ports scanned by the "common" preset — the
// ports a service is most likely to be listening on, in rough order of
// how often they show up in the wild.
var wellKnownPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
	27017, 5000, 8000, 8888, 9000, 9090, 9200,
}

// CommonPorts returns a copy of the well-known port preset, sorted.
func CommonPorts() []int {
	out := make([]int, len(wellKnownPorts))
	copy(out, wellKnownPorts)
	sort.Ints(out)
	return out
}

// ParsePortSpec parses a port specification into a sorted, deduplicated
// list of port numbers. Accepted forms:
//
//	"80"            single port
//	"80,443,8080"   comma-separated list
//	"8000-8010"     inclusive range
//	"common"        the well-known preset
//
// Forms can be mixed: "80,8000-8002,443". Ports must be in 1..65535.
func ParsePortSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}
	if strings.EqualFold(spec, "common") {
		return CommonPorts(), nil
	}

	seen := map[int]struct{}{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty element in port specification %q", spec)
		}
		ports, err := parsePortPart(part)
		if err != nil {
			return nil, err
		}
		for _, p := range ports {
			seen[p] = struct{}{}
		}
	}

	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func parsePortPart(part string) ([]int, error) {
	if strings.Contains(part, "-") {
		bounds := strings.SplitN(part, "-", 2)
		if len(bounds) != 2 || bounds[0] == "" || bounds[1] == "" {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		lo, err := parsePort(bounds[0])
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q: %w", part, err)
		}
		hi, err := parsePort(bounds[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q: %w", part, err)
		}
		if lo > hi {
			return nil, fmt.Errorf("invalid port range %q: start %d is greater than end %d", part, lo, hi)
		}
		ports := make([]int, 0, hi-lo+1)
		for p := lo; p <= hi; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}
	p, err := parsePort(part)
	if err != nil {
		return nil, err
	}
	return []int{p}, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: not a number", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %d: must be between 1 and 65535", p)
	}
	return p, nil
}
