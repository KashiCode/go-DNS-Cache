package main

import (
    "encoding/binary"
    "strings"
)

// parseQName decodes a domain name from the DNS QNAME format.
func parseQName(data []byte, offset int) (string, int) {
    labels := []string{}
    for {
        if offset >= len(data) {
            return "", offset
        }
        length := int(data[offset])
        offset++
        if length == 0 {
            break
        }
        if offset+length > len(data) {
            return "", offset
        }
        labels = append(labels, string(data[offset:offset+length]))
        offset += length
    }
    return strings.Join(labels, "."), offset
}

// normalizeDomain ensures domain names are lowercase and stripped of trailing dot.
func normalizeDomain(name string) string {
    name = strings.ToLower(name)
    return strings.TrimSuffix(name, ".")
}

// extractTTL extracts the TTL value from the first answer in a DNS response.
// It handles name compression and skips over the correct fields to find TTL.
func extractTTL(data []byte) uint32 {
    if len(data) < 12 {
        return 0
    }

    qdCount := int(binary.BigEndian.Uint16(data[4:6]))
    anCount := int(binary.BigEndian.Uint16(data[6:8]))
    offset := 12

    // Skip over all questions
    for i := 0; i < qdCount; i++ {
        for {
            if offset >= len(data) {
                return 0
            }
            length := int(data[offset])
            offset++
            if length == 0 {
                break
            }
            offset += length
        }
        offset += 4 // Type + Class
    }

    if anCount == 0 {
        return 0
    }

    // Handle answer section name (compressed or full label)
    if offset >= len(data) {
        return 0
    }

    if data[offset]&0xC0 == 0xC0 {
        // Compressed pointer name
        offset += 2
    } else {
        // Full label name (unlikely here)
        for {
            if offset >= len(data) {
                return 0
            }
            length := int(data[offset])
            offset++
            if length == 0 {
                break
            }
            offset += length
        }
    }

    // Ensure space for Type (2) + Class (2) + TTL (4)
    if offset+8 > len(data) {
        return 0
    }

    offset += 4 // Skip Type and Class

    // Now we're at TTL
    return binary.BigEndian.Uint32(data[offset : offset+4])
}
