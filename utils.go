package main

import (
    "encoding/binary"
    "strings"
)


func extractTTL(data []byte) uint32 {
    if len(data) < 12 {
        return 0
    }

    qdCount := binary.BigEndian.Uint16(data[4:6])
    offset := 12

 
    for i := 0; i < int(qdCount); i++ {
        for {
            length := int(data[offset])
            offset++
            if length == 0 {
                break
            }
            offset += length
        }
        offset += 4 
    }

    
    if offset+10 > len(data) {
        return 0
    }

 
    ttl := binary.BigEndian.Uint32(data[ttlOffset : ttlOffset+4])
    return ttl
}


func normalizeDomain(name string) string {
    name = strings.ToLower(name)
    return strings.TrimSuffix(name, ".")
}
