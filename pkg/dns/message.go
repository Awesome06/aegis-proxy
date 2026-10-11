package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Supported DNS Record Types (RFC 1035 / RFC 3596)
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeAAAA  uint16 = 28
	ClassIN   uint16 = 1
)

var (
	// ErrTruncatedPacket indicates packet length was shorter than expected.
	ErrTruncatedPacket = errors.New("dns packet truncated")
	// ErrInvalidTxID indicates mismatched transaction identifier.
	ErrInvalidTxID = errors.New("dns transaction ID mismatch")
	// ErrNamePointerLoop indicates circular reference in compressed DNS names.
	ErrNamePointerLoop = errors.New("dns compression pointer loop detected")
	// ErrNoAnswers indicates no matching address records were returned.
	ErrNoAnswers = errors.New("no dns address records found in response")
	// ErrServerFailure indicates upstream DNS server returned non-zero RCODE.
	ErrServerFailure = errors.New("dns server returned error status code")
)

// BuildQuery constructs an RFC 1035 compliant binary DNS query payload.
// Wire format: 12-byte header followed by length-prefixed QNAME, QTYPE, and QCLASS.
func BuildQuery(txID uint16, hostname string, qtype uint16) ([]byte, error) {
	hostname = strings.TrimSuffix(hostname, ".")
	if hostname == "" {
		return nil, errors.New("empty hostname for dns query")
	}

	// 12 bytes header + estimated QNAME length + 4 bytes (QTYPE + QCLASS)
	buf := make([]byte, 12, 12+len(hostname)+6)

	// Header: ID (2 bytes)
	binary.BigEndian.PutUint16(buf[0:2], txID)
	// Flags: Standard query with Recursion Desired (RD = 1) -> 0x0100
	buf[2] = 0x01
	buf[3] = 0x00
	// QDCOUNT = 1 (1 question)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	// ANCOUNT = 0
	binary.BigEndian.PutUint16(buf[6:8], 0)
	// NSCOUNT = 0
	binary.BigEndian.PutUint16(buf[8:10], 0)
	// ARCOUNT = 0
	binary.BigEndian.PutUint16(buf[10:12], 0)

	// Question Section: QNAME
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		labelLen := len(label)
		if labelLen == 0 || labelLen > 63 {
			return nil, fmt.Errorf("invalid dns label length %d in hostname %q", labelLen, hostname)
		}
		buf = append(buf, byte(labelLen))
		buf = append(buf, label...)
	}
	// Terminating zero byte for root domain
	buf = append(buf, 0x00)

	// QTYPE & QCLASS
	var typeClass [4]byte
	binary.BigEndian.PutUint16(typeClass[0:2], qtype)
	binary.BigEndian.PutUint16(typeClass[2:4], ClassIN)
	buf = append(buf, typeClass[:]...)

	return buf, nil
}

// ParseResponse extracts resolved IP addresses and minimum TTL from an RFC 1035 response payload.
// It safely handles pointer decompression (0xC0) with recursion limits to prevent cyclic attacks.
func ParseResponse(raw []byte, expectedTxID uint16) ([]net.IP, uint32, error) {
	if len(raw) < 12 {
		return nil, 0, ErrTruncatedPacket
	}

	// Verify Transaction ID
	txID := binary.BigEndian.Uint16(raw[0:2])
	if expectedTxID != 0 && txID != expectedTxID {
		return nil, 0, fmt.Errorf("%w: expected %d, got %d", ErrInvalidTxID, expectedTxID, txID)
	}

	// Check RCODE (bits 0-3 of byte 3)
	rcode := raw[3] & 0x0F
	if rcode != 0 {
		return nil, 0, fmt.Errorf("%w: RCODE=%d", ErrServerFailure, rcode)
	}

	qdCount := binary.BigEndian.Uint16(raw[4:6])
	anCount := binary.BigEndian.Uint16(raw[6:8])

	offset := 12

	// Skip Question Section
	for i := 0; i < int(qdCount); i++ {
		_, nextOffset, err := parseName(raw, offset, 0)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse question name: %w", err)
		}
		// QTYPE (2) + QCLASS (2) = 4 bytes
		if nextOffset+4 > len(raw) {
			return nil, 0, ErrTruncatedPacket
		}
		offset = nextOffset + 4
	}

	var ips []net.IP
	var minTTL uint32 = 0xFFFFFFFF

	// Parse Answer Section
	for i := 0; i < int(anCount); i++ {
		if offset >= len(raw) {
			break
		}

		_, nextOffset, err := parseName(raw, offset, 0)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse answer name: %w", err)
		}
		offset = nextOffset

		// TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes
		if offset+10 > len(raw) {
			return nil, 0, ErrTruncatedPacket
		}

		rrType := binary.BigEndian.Uint16(raw[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(raw[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(raw[offset+4 : offset+8])
		rdLength := binary.BigEndian.Uint16(raw[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(raw) {
			return nil, 0, ErrTruncatedPacket
		}

		if rrClass == ClassIN {
			if rrType == TypeA && rdLength == 4 {
				ip := net.IPv4(raw[offset], raw[offset+1], raw[offset+2], raw[offset+3])
				ips = append(ips, ip)
				if ttl < minTTL {
					minTTL = ttl
				}
			} else if rrType == TypeAAAA && rdLength == 16 {
				ip := make(net.IP, 16)
				copy(ip, raw[offset:offset+16])
				ips = append(ips, ip)
				if ttl < minTTL {
					minTTL = ttl
				}
			}
		}

		offset += int(rdLength)
	}

	if len(ips) == 0 {
		return nil, 0, ErrNoAnswers
	}

	// Clamp minimum TTL to at least 10 seconds to avoid rapid cache thrashing
	if minTTL < 10 {
		minTTL = 10
	}

	return ips, minTTL, nil
}

// parseName extracts a DNS domain name from the raw byte stream at the given offset.
// Supports both label sequences and RFC 1035 compressed pointers (0xC0).
func parseName(raw []byte, offset int, depth int) (string, int, error) {
	if depth > 10 {
		return "", 0, ErrNamePointerLoop
	}

	var labels []string
	curr := offset
	jumped := false
	bytesConsumed := 0

	for {
		if curr >= len(raw) {
			return "", 0, ErrTruncatedPacket
		}

		length := raw[curr]

		// Zero byte terminates domain name
		if length == 0 {
			if !jumped {
				bytesConsumed = curr - offset + 1
			}
			break
		}

		// Pointer check: two high bits set (0xC0)
		if (length & 0xC0) == 0xC0 {
			if curr+2 > len(raw) {
				return "", 0, ErrTruncatedPacket
			}
			ptrOffset := int(binary.BigEndian.Uint16(raw[curr:curr+2]) & 0x3FFF)
			if !jumped {
				bytesConsumed = curr - offset + 2
				jumped = true
			}

			// Follow pointer recursively
			targetName, _, err := parseName(raw, ptrOffset, depth+1)
			if err != nil {
				return "", 0, err
			}
			if targetName != "" {
				labels = append(labels, targetName)
			}
			break
		}

		// Normal label
		curr++
		labelEnd := curr + int(length)
		if labelEnd > len(raw) {
			return "", 0, ErrTruncatedPacket
		}
		labels = append(labels, string(raw[curr:labelEnd]))
		curr = labelEnd

		if !jumped {
			bytesConsumed = curr - offset + 1
		}
	}

	return strings.Join(labels, "."), offset + bytesConsumed, nil
}
