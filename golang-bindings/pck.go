package dcap

import (
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// GetValue looks up an arbitrary OID in the Intel SGX extension.
// It performs recursive ASN.1 DER traversal on RawExtension bytes.
// Returns (nil, nil) if the OID is not found.
func (ext *PCKExtension) GetValue(oid string) ([]byte, error) {
	oidBytes, err := encodeOIDBytes(oid)
	if err != nil {
		return nil, fmt.Errorf("dcap: invalid OID %q: %w", oid, err)
	}
	return findRecursive(oidBytes, ext.RawExtension)
}

// encodeOIDBytes converts a dotted OID string (e.g. "1.2.840.113741.1.13.1.1")
// to DER-encoded OID value bytes (without the tag and length).
func encodeOIDBytes(oid string) ([]byte, error) {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("OID must have at least 2 components")
	}

	arcs := make([]int, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid OID component %q: %w", p, err)
		}
		if v < 0 {
			return nil, fmt.Errorf("negative OID component %d", v)
		}
		arcs[i] = v
	}

	oidASN := asn1.ObjectIdentifier(arcs)
	// Marshal the full OID TLV, then strip tag+length to get just the value bytes.
	full, err := asn1.Marshal(oidASN)
	if err != nil {
		return nil, err
	}
	// full is: tag (0x06) + length + value. Parse to extract value.
	// We can use asn1.Unmarshal to verify, but simpler to just skip TLV header.
	if len(full) < 2 || full[0] != 0x06 {
		return nil, fmt.Errorf("unexpected ASN.1 OID encoding")
	}
	// Skip tag byte, then parse length
	_, offset, err := parseDERLength(full[1:])
	if err != nil {
		return nil, err
	}
	return full[1+offset:], nil
}

// parseDERLength parses a DER length field. Returns (length, bytesConsumed, error).
func parseDERLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty length field")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, 0, fmt.Errorf("unsupported DER length encoding")
	}
	if len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("truncated DER length")
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

// parseDERElement parses a single DER TLV element from data.
// Returns (tag, value, totalBytesConsumed, error).
func parseDERElement(data []byte) (byte, []byte, int, error) {
	if len(data) < 2 {
		return 0, nil, 0, fmt.Errorf("truncated DER element")
	}
	tag := data[0]
	length, lenSize, err := parseDERLength(data[1:])
	if err != nil {
		return 0, nil, 0, err
	}
	headerSize := 1 + lenSize
	if len(data) < headerSize+length {
		return 0, nil, 0, fmt.Errorf("truncated DER value")
	}
	return tag, data[headerSize : headerSize+length], headerSize + length, nil
}

// parseSequenceChildren parses the children of a SEQUENCE value (the inner bytes).
// Returns a slice of (tag, value) pairs.
func parseSequenceChildren(data []byte) ([][2][]byte, error) {
	var children [][2][]byte
	offset := 0
	for offset < len(data) {
		tag, value, consumed, err := parseDERElement(data[offset:])
		if err != nil {
			return nil, err
		}
		// Store tag as a single byte slice for convenience
		children = append(children, [2][]byte{{tag}, value})
		offset += consumed
	}
	return children, nil
}

const tagSequence = 0x30
const tagOID = 0x06

// findRecursive searches a DER SEQUENCE for an entry whose OID matches oidBytes.
// The structure is: SEQUENCE { SEQUENCE { OID, Value }, SEQUENCE { OID, Value }, ... }
// If a Value is itself a SEQUENCE, it recurses into it.
func findRecursive(oidBytes []byte, data []byte) ([]byte, error) {
	// Parse outer element
	tag, seqValue, _, err := parseDERElement(data)
	if err != nil {
		return nil, nil // can't parse, not found
	}
	if tag != tagSequence {
		return nil, nil
	}
	return findInSequenceValue(oidBytes, seqValue)
}

func findInSequenceValue(oidBytes []byte, seqValue []byte) ([]byte, error) {
	children, err := parseSequenceChildren(seqValue)
	if err != nil {
		return nil, nil // can't parse children, not found
	}

	for _, child := range children {
		childTag := child[0][0]
		childValue := child[1]

		if childTag != tagSequence {
			continue
		}

		// Parse this SEQUENCE entry to get [OID, Value]
		entryChildren, err := parseSequenceChildren(childValue)
		if err != nil || len(entryChildren) < 2 {
			continue
		}

		nameTag := entryChildren[0][0][0]
		nameValue := entryChildren[0][1]
		valueTag := entryChildren[1][0][0]
		valueBytes := entryChildren[1][1]

		if nameTag == tagOID && bytesEqual(nameValue, oidBytes) {
			return valueBytes, nil
		}

		// If the value is a SEQUENCE, recurse into it
		if valueTag == tagSequence {
			found, err := findInSequenceValue(oidBytes, valueBytes)
			if err != nil {
				return nil, err
			}
			if found != nil {
				return found, nil
			}
		}
	}

	return nil, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
