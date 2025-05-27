package main

import (
    "encoding/binary"
    "strings"
    "time"
)


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


func normalizeDomain(name string) string {
    name = strings.ToLower(name)
    return strings.TrimSuffix(name, ".")
}


func extractTTL(data []byte) uint32 {
    if len(data) < 12 {
        return 0
    }

    qdCount := int(binary.BigEndian.Uint16(data[4:6]))
    anCount := int(binary.BigEndian.Uint16(data[6:8]))
    offset := 12

    
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
        offset += 4 
    }

    if anCount == 0 {
        return 0
    }

    
    if offset >= len(data) {
        return 0
    }

    if data[offset]&0xC0 == 0xC0 {
        
        offset += 2
    } else {
        
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

    
    if offset+8 > len(data) {
        return 0
    }

    offset += 4 

    
    return binary.BigEndian.Uint32(data[offset : offset+4])
}

func extractCNAME(data []byte) (string, bool) {
    if len(data) < 12 {
        return "", false
    }

    qdCount := int(binary.BigEndian.Uint16(data[4:6]))
    anCount := int(binary.BigEndian.Uint16(data[6:8]))
    offset := 12

    
    for i := 0; i < qdCount; i++ {
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

    
    for i := 0; i < anCount; i++ {
        if offset+10 > len(data) {
            return "", false
        }

        
        if data[offset]&0xC0 == 0xC0 {
            offset += 2
        } else {
            for {
                length := int(data[offset])
                offset++
                if length == 0 {
                    break
                }
                offset += length
            }
        }

        typ := binary.BigEndian.Uint16(data[offset : offset+2])
        offset += 8

        rdLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
        offset += 2

        if typ == 5 { 
            cname, _ := parseQName(data, offset)
            return cname, true
        }

        offset += rdLength
    }

    return "", false
}

func buildDNSQuery(name string, qtype uint16, qclass uint16) []byte {
    id := uint16(time.Now().UnixNano() & 0xFFFF)
    header := make([]byte, 12)
    binary.BigEndian.PutUint16(header[0:2], id)
    binary.BigEndian.PutUint16(header[2:4], 0x0100) 
    binary.BigEndian.PutUint16(header[4:6], 1)     

    qname := []byte{}
    for _, label := range strings.Split(name, ".") {
        qname = append(qname, byte(len(label)))
        qname = append(qname, []byte(label)...)
    }
    qname = append(qname, 0) 

    question := make([]byte, 4)
    binary.BigEndian.PutUint16(question[0:2], qtype)
    binary.BigEndian.PutUint16(question[2:4], qclass)

    return append(append(header, qname...), question...)
}

