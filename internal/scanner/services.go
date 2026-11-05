package scanner

import "strings"

// serviceNames maps well-known ports to the service usually found there.
// It is a hint, not a guarantee — the banner check in ServiceFromBanner
// refines it when a service announces itself.
var serviceNames = map[int]string{
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	67:    "dhcp",
	68:    "dhcp",
	69:    "tftp",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	123:   "ntp",
	135:   "msrpc",
	139:   "netbios",
	143:   "imap",
	161:   "snmp",
	162:   "snmp-trap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	514:   "syslog",
	587:   "smtp-submission",
	636:   "ldaps",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1433:  "mssql",
	1521:  "oracle",
	1723:  "pptp",
	2049:  "nfs",
	2181:  "zookeeper",
	2375:  "docker",
	2376:  "docker-tls",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgres",
	5900:  "vnc",
	5985:  "winrm",
	6379:  "redis",
	6443:  "kubernetes",
	8080:  "http-alt",
	8443:  "https-alt",
	9000:  "php-fpm",
	9090:  "prometheus",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
	50000: "db2",
}

// ServiceName returns the conventional service name for a port, or
// "unknown" when the port has no well-known assignment.
func ServiceName(port int) string {
	if name, ok := serviceNames[port]; ok {
		return name
	}
	return "unknown"
}

// bannerPrefixes matches the first bytes a service sends on connect to
// the service that sent them. SSH, SMTP, FTP, MySQL and Redis all
// announce themselves; HTTP stays silent and is identified by port.
var bannerPrefixes = []struct {
	prefix  string
	service string
}{
	{"SSH-", "ssh"},
	{"220 ", "smtp"}, // SMTP / FTP greeting (refined by port when known)
	{"220-", "smtp"},
	{"+OK", "pop3"},
	{"* OK", "imap"},
}

// ServiceFromBanner identifies a service from its connect banner.
// It returns "" when the banner does not identify the service.
func ServiceFromBanner(banner string) string {
	if banner == "" {
		return ""
	}
	// Redis answers a probe with "-ERR" / "+PONG" style replies.
	if strings.HasPrefix(banner, "-ERR") || strings.HasPrefix(banner, "+PONG") {
		return "redis"
	}
	for _, bp := range bannerPrefixes {
		if strings.HasPrefix(banner, bp.prefix) {
			return bp.service
		}
	}
	return ""
}
