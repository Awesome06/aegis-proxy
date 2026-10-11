package tlsinspector

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	// ErrTooShort indicates the buffer is smaller than minimum TLS record headers.
	ErrTooShort = errors.New("tls record buffer too short")
	// ErrNotTLS indicates the packet does not match the TLS Record header.
	ErrNotTLS = errors.New("not a valid tls packet")
	// ErrNotClientHello indicates the handshake message is not a ClientHello (0x01).
	ErrNotClientHello = errors.New("handshake is not client_hello")
	// ErrSNINotFound indicates the ClientHello does not contain the SNI extension.
	ErrSNINotFound = errors.New("sni extension not found in client_hello")
	// ErrMalformedRecord indicates unexpected internal length or boundary violations.
	ErrMalformedRecord = errors.New("malformed tls record protocol framing")
)

// ClientHelloInfo holds extracted metadata from a zero-termination inspection pass.
type ClientHelloInfo struct {
	SNI        string
	ALPNProtos []string
	Version    uint16
}

// IsTLS returns true if the leading bytes match a TLS Handshake record (0x16).
func IsTLS(record []byte) bool {
	if len(record) < 5 {
		return false
	}
	// ContentType must be Handshake (0x16) and major version must be 3 (SSL 3.0 / TLS 1.x)
	return record[0] == 0x16 && record[1] == 0x03
}

// ParseClientHello inspects the raw TLS byte slice, navigates the RFC 5246/8446 structures,
// and extracts the SNI hostname and ALPN advertised protocols without decrypting or terminating TLS.
// All slices are strictly bounds-checked to guarantee memory safety.
func ParseClientHello(record []byte) (*ClientHelloInfo, error) {
	if len(record) < 44 {
		return nil, ErrTooShort
	}

	// 1. Validate Record Layer
	// Record ContentType (0x16) and Handshake Type ClientHello (0x01)
	if record[0] != 0x16 || record[5] != 0x01 {
		return nil, ErrNotClientHello
	}

	// Record length validation
	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+recordLen {
		// Even if the entire record wasn't buffered, we verify minimum bounds
		if len(record) < 44 {
			return nil, ErrTooShort
		}
	}

	clientVersion := binary.BigEndian.Uint16(record[9:11])

	// 2. Navigate Session ID
	// Byte 43 is Session ID Length
	sessionIDLen := int(record[43])
	cipherSuiteOffset := 44 + sessionIDLen
	if len(record) < cipherSuiteOffset+2 {
		return nil, ErrMalformedRecord
	}

	// 3. Navigate Cipher Suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(record[cipherSuiteOffset : cipherSuiteOffset+2]))
	compMethodsOffset := cipherSuiteOffset + 2 + cipherSuitesLen
	if len(record) < compMethodsOffset+1 {
		return nil, ErrMalformedRecord
	}

	// 4. Navigate Compression Methods
	compMethodsLen := int(record[compMethodsOffset])
	extOffset := compMethodsOffset + 1 + compMethodsLen
	if len(record) < extOffset+2 {
		// Valid ClientHello without extensions
		return &ClientHelloInfo{Version: clientVersion}, nil
	}

	// 5. Navigate Extensions Block
	extensionsLen := int(binary.BigEndian.Uint16(record[extOffset : extOffset+2]))
	curr := extOffset + 2
	extEnd := curr + extensionsLen
	if extEnd > len(record) {
		extEnd = len(record)
	}

	info := &ClientHelloInfo{
		Version: clientVersion,
	}

	for curr+4 <= extEnd {
		extType := binary.BigEndian.Uint16(record[curr : curr+2])
		extLen := int(binary.BigEndian.Uint16(record[curr+2 : curr+4]))
		curr += 4

		if curr+extLen > extEnd {
			break
		}
		extData := record[curr : curr+extLen]
		curr += extLen

		switch extType {
		case 0x0000: // Server Name Indication (SNI) - RFC 6066
			sni, err := extractSNI(extData)
			if err == nil && sni != "" {
				info.SNI = sni
			}

		case 0x0010: // ALPN (Application-Layer Protocol Negotiation) - RFC 7301
			protos := extractALPN(extData)
			if len(protos) > 0 {
				info.ALPNProtos = protos
			}
		}
	}

	return info, nil
}

// extractSNI parses the Server Name extension data block.
func extractSNI(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrMalformedRecord
	}
	serverNameListLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+serverNameListLen {
		return "", ErrMalformedRecord
	}

	curr := 2
	end := 2 + serverNameListLen
	for curr+3 <= end {
		nameType := data[curr]
		nameLen := int(binary.BigEndian.Uint16(data[curr+1 : curr+3]))
		curr += 3

		if curr+nameLen > end {
			return "", ErrMalformedRecord
		}

		if nameType == 0x00 { // host_name
			hostName := string(data[curr : curr+nameLen])
			return strings.ToLower(hostName), nil
		}
		curr += nameLen
	}

	return "", ErrSNINotFound
}

// extractALPN parses advertised protocol names (e.g. "h2", "http/1.1").
func extractALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	alpnListLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+alpnListLen {
		return nil
	}

	var protos []string
	curr := 2
	end := 2 + alpnListLen
	for curr < end {
		protoLen := int(data[curr])
		curr++
		if curr+protoLen > end {
			break
		}
		protos = append(protos, string(data[curr:curr+protoLen]))
		curr += protoLen
	}
	return protos
}
