package zeek

import (
	"encoding/json"
	"strings"
	"time"
)

// X509Record represents a parsed Zeek x509.log entry.
type X509Record struct {
	Timestamp     time.Time
	FileID        string
	Fingerprint   string
	SubjectCN     string
	SubjectOrg    string
	SubjectFull   string
	IssuerCN      string
	IssuerOrg     string
	IssuerFull    string
	Serial        string
	NotValidBefore time.Time
	NotValidAfter  time.Time
	KeyAlg        string
	KeyType       string
	KeyLength     int
	SigAlg        string
	SANsDNS       []string
	SANsIP        []string
	SANsEmail     []string
	IsCA          bool
	Version       int
}

// SSLRecord represents a parsed Zeek ssl.log entry.
type SSLRecord struct {
	Timestamp    time.Time
	UID          string
	ClientIP     string
	ClientPort   int
	ServerIP     string
	ServerPort   int
	Version      string
	Cipher       string
	ServerName   string
	Established  bool
	JA3          string
	JA3S         string
	CertChainFPs []string
}

// ConnRecord represents a parsed Zeek conn.log entry.
type ConnRecord struct {
	Timestamp  time.Time
	UID        string
	ClientIP   string
	ClientPort int
	ServerIP   string
	ServerPort int
	Proto      string
	Duration   float64
	OrigBytes  int64
	RespBytes  int64
	ConnState  string
}

// rawX509 maps Zeek's dotted JSON key names to struct fields.
type rawX509 struct {
	Ts             float64  `json:"ts"`
	ID             string   `json:"id"`
	Version        int      `json:"certificate.version"`
	Serial         string   `json:"certificate.serial"`
	Subject        string   `json:"certificate.subject"`
	Issuer         string   `json:"certificate.issuer"`
	NotValidBefore float64  `json:"certificate.not_valid_before"`
	NotValidAfter  float64  `json:"certificate.not_valid_after"`
	KeyAlg         string   `json:"certificate.key_alg"`
	SigAlg         string   `json:"certificate.sig_alg"`
	KeyType        string   `json:"certificate.key_type"`
	KeyLength      int      `json:"certificate.key_length"`
	SANsDNS        []string `json:"san.dns"`
	SANsIP         []string `json:"san.ip"`
	SANsEmail      []string `json:"san.email"`
	IsCA           bool     `json:"basic_constraints.ca"`
	Fingerprint    string   `json:"fingerprint"`
}

// rawSSL maps Zeek's dotted JSON key names for ssl.log entries.
type rawSSL struct {
	Ts           float64  `json:"ts"`
	UID          string   `json:"uid"`
	OrigH        string   `json:"id.orig_h"`
	OrigP        int      `json:"id.orig_p"`
	RespH        string   `json:"id.resp_h"`
	RespP        int      `json:"id.resp_p"`
	Version      string   `json:"version"`
	Cipher       string   `json:"cipher"`
	ServerName   string   `json:"server_name"`
	Established  bool     `json:"established"`
	JA3          string   `json:"ja3"`
	JA3S         string   `json:"ja3s"`
	CertChainFPs []string `json:"cert_chain_fps"`
}

// rawConn maps Zeek's dotted JSON key names for conn.log entries.
type rawConn struct {
	Ts        float64 `json:"ts"`
	UID       string  `json:"uid"`
	OrigH     string  `json:"id.orig_h"`
	OrigP     int     `json:"id.orig_p"`
	RespH     string  `json:"id.resp_h"`
	RespP     int     `json:"id.resp_p"`
	Proto     string  `json:"proto"`
	Duration  float64 `json:"duration"`
	OrigBytes int64   `json:"orig_bytes"`
	RespBytes int64   `json:"resp_bytes"`
	ConnState string  `json:"conn_state"`
}

// ParseX509Record parses a Zeek x509.log JSON line into an X509Record.
func ParseX509Record(data []byte) (*X509Record, error) {
	var raw rawX509
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	subjectCN, subjectOrg := parseDN(raw.Subject)
	issuerCN, issuerOrg := parseDN(raw.Issuer)

	return &X509Record{
		Timestamp:      unixToTime(raw.Ts),
		FileID:         raw.ID,
		Fingerprint:    raw.Fingerprint,
		SubjectCN:      subjectCN,
		SubjectOrg:     subjectOrg,
		SubjectFull:    raw.Subject,
		IssuerCN:       issuerCN,
		IssuerOrg:      issuerOrg,
		IssuerFull:     raw.Issuer,
		Serial:         raw.Serial,
		NotValidBefore: unixToTime(raw.NotValidBefore),
		NotValidAfter:  unixToTime(raw.NotValidAfter),
		KeyAlg:         raw.KeyAlg,
		KeyType:        raw.KeyType,
		KeyLength:      raw.KeyLength,
		SigAlg:         raw.SigAlg,
		SANsDNS:        raw.SANsDNS,
		SANsIP:         raw.SANsIP,
		SANsEmail:      raw.SANsEmail,
		IsCA:           raw.IsCA,
		Version:        raw.Version,
	}, nil
}

// ParseSSLRecord parses a Zeek ssl.log JSON line into an SSLRecord.
func ParseSSLRecord(data []byte) (*SSLRecord, error) {
	var raw rawSSL
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return &SSLRecord{
		Timestamp:    unixToTime(raw.Ts),
		UID:          raw.UID,
		ClientIP:     raw.OrigH,
		ClientPort:   raw.OrigP,
		ServerIP:     raw.RespH,
		ServerPort:   raw.RespP,
		Version:      raw.Version,
		Cipher:       raw.Cipher,
		ServerName:   raw.ServerName,
		Established:  raw.Established,
		JA3:          raw.JA3,
		JA3S:         raw.JA3S,
		CertChainFPs: raw.CertChainFPs,
	}, nil
}

// ParseConnRecord parses a Zeek conn.log JSON line into a ConnRecord.
func ParseConnRecord(data []byte) (*ConnRecord, error) {
	var raw rawConn
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return &ConnRecord{
		Timestamp:  unixToTime(raw.Ts),
		UID:        raw.UID,
		ClientIP:   raw.OrigH,
		ClientPort: raw.OrigP,
		ServerIP:   raw.RespH,
		ServerPort: raw.RespP,
		Proto:      raw.Proto,
		Duration:   raw.Duration,
		OrigBytes:  raw.OrigBytes,
		RespBytes:  raw.RespBytes,
		ConnState:  raw.ConnState,
	}, nil
}

// unixToTime converts a Unix epoch float (seconds.microseconds) to time.Time.
func unixToTime(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}

// parseDN extracts CommonName and Organization from a Zeek-style DN string.
// Zeek formats DNs like "CN=example.com,O=Example Inc.,C=US".
func parseDN(dn string) (cn, org string) {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			cn = strings.TrimPrefix(part, "CN=")
		} else if strings.HasPrefix(part, "O=") {
			org = strings.TrimPrefix(part, "O=")
		}
	}
	return cn, org
}
