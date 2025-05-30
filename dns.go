package main

import (
    "encoding/binary"
    "fmt"
    "net"
    "time"
    "log"
)

var rootServers = []string{
    "198.41.0.4:53",     // A-root
    "199.9.14.201:53",   // B-root
    "192.33.4.12:53",    // C-root
    "199.7.91.13:53",    // D-root
    "192.203.230.10:53", // E-root
}

type DNSHeader struct {
    ID                                 uint16
    Flags                              uint16
    QDCount, ANCount, NSCount, ARCount uint16
}

type DNSQuestion struct {
    Name  string
    Type  uint16
    Class uint16
}

func parseDNSQuery(data []byte) (DNSHeader, DNSQuestion, error) {
    if len(data) < 12 {
        return DNSHeader{}, DNSQuestion{}, fmt.Errorf("data too short")
    }

    header := DNSHeader{
        ID:      binary.BigEndian.Uint16(data[0:2]),
        Flags:   binary.BigEndian.Uint16(data[2:4]),
        QDCount: binary.BigEndian.Uint16(data[4:6]),
        ANCount: binary.BigEndian.Uint16(data[6:8]),
        NSCount: binary.BigEndian.Uint16(data[8:10]),
        ARCount: binary.BigEndian.Uint16(data[10:12]),
    }

    qname, offset := parseQName(data, 12)
    if offset+4 > len(data) {
        return header, DNSQuestion{}, fmt.Errorf("incomplete question section")
    }

    question := DNSQuestion{
        Name:  qname,
        Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
        Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
    }

    return header, question, nil
}

func resolveRecursively(query []byte) ([]byte, error) {
    currentServers := rootServers

    for i := 0; i < 15; i++ {
        var lastErr error

        for _, server := range currentServers {
            log.Println("Querying server:", server)

            conn, err := net.Dial("udp", server)
            if err != nil {
                log.Println("Dial error:", err)
                lastErr = err
                continue
            }

            conn.SetDeadline(time.Now().Add(3 * time.Second))
            _, err = conn.Write(query)
            if err != nil {
                log.Println("Write error:", err)
                conn.Close()
                lastErr = err
                continue
            }

            buf := make([]byte, 4096)
            n, err := conn.Read(buf)
            conn.Close()
            if err != nil {
                log.Println("Read error:", err)
                lastErr = err
                continue
            }

            response := buf[:n]
            log.Printf("Response received (%d bytes)\n", n)

            anCount := binary.BigEndian.Uint16(response[6:8])
            if anCount > 0 {
                log.Println("Answer found")
                return response, nil
            }

            glueIPs, nsNames := extractNextServers(response)
            log.Println("Glue IPs:", glueIPs)
            log.Println("NS Names:", nsNames)

            var newServers []string

            if len(glueIPs) > 0 {
                newServers = glueIPs
            } else {
                for _, ns := range nsNames {
                    log.Println("Resolving NS:", ns)
                    nsQuery := buildDNSQuery(ns, 1, 1)
                    nsResp, err := resolveRecursively(nsQuery)
                    if err != nil {
                        continue
                    }
                    ip := extractARecord(nsResp)
                    if ip != "" {
                        log.Println("Resolved NS IP:", ip)
                        newServers = append(newServers, ip+":53")
                    }
                }
            }

            if len(newServers) == 0 {
                return response, nil
            }

            currentServers = newServers
            break
        }

        if len(currentServers) == 0 {
            return nil, lastErr
        }
    }

    return nil, fmt.Errorf("recursion failed")
}

func extractNextServers(resp []byte) (ips []string, names []string) {
    if len(resp) < 12 {
        return
    }

    qdCount := int(binary.BigEndian.Uint16(resp[4:6]))
    anCount := int(binary.BigEndian.Uint16(resp[6:8]))
    nsCount := int(binary.BigEndian.Uint16(resp[8:10]))
    arCount := int(binary.BigEndian.Uint16(resp[10:12]))

    offset := 12
    for i := 0; i < qdCount; i++ {
        offset = skipQName(resp, offset)
        offset += 4
    }

    for i := 0; i < anCount; i++ {
        offset = skipRR(resp, offset)
    }

    for i := 0; i < nsCount; i++ {
        start := offset
        offset = skipRR(resp, offset)
        if offset == -1 || start+12 > len(resp) {
            continue
        }

        rrType := binary.BigEndian.Uint16(resp[start+2 : start+4])
        if rrType == 2 {
            nsName := extractName(resp, start+12)
            if nsName != "" {
                names = append(names, nsName)
            }
        }
    }

    for i := 0; i < arCount; i++ {
        start := offset
        offset = skipRR(resp, offset)
        if offset == -1 || start+12 > len(resp) {
            continue
        }

        rrType := binary.BigEndian.Uint16(resp[start+2 : start+4])
        if rrType == 1 {
            rdLength := int(binary.BigEndian.Uint16(resp[start+10 : start+12]))
            rdata := resp[start+12 : start+12+rdLength]
            if len(rdata) == 4 {
                ip := net.IP(rdata).String()
                ips = append(ips, ip+":53")
            }
        }
    }

    return
}

func skipRR(data []byte, offset int) int {
    if offset+10 > len(data) {
        return -1
    }

    offset = skipQName(data, offset)
    if offset+10 > len(data) {
        return -1
    }

    rdlength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
    offset += 10 + rdlength
    return offset
}

func skipQName(data []byte, offset int) int {
    for {
        if offset >= len(data) {
            return -1
        }
        length := int(data[offset])
        if length == 0 {
            return offset + 1
        }
        if length&0xC0 == 0xC0 {
            return offset + 2
        }
        offset += length + 1
    }
}

func extractName(data []byte, offset int) string {
    var name string
    for {
        if offset >= len(data) {
            return ""
        }
        length := int(data[offset])
        if length&0xC0 == 0xC0 {
            if offset+1 >= len(data) {
                return ""
            }
            pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
            suffix := extractName(data, pointer)
            if suffix != "" {
                if name != "" {
                    name += "."
                }
                name += suffix
            }
            return name
        }
        if length == 0 {
            offset++
            break
        }
        offset++
        if offset+length > len(data) {
            return ""
        }
        if name != "" {
            name += "."
        }
        name += string(data[offset : offset+length])
        offset += length
    }
    return name
}

func extractARecord(resp []byte) string {
    offset := 12
    qdCount := int(binary.BigEndian.Uint16(resp[4:6]))
    for i := 0; i < qdCount; i++ {
        offset = skipQName(resp, offset)
        offset += 4
    }

    for offset < len(resp) {
        if offset+12 > len(resp) {
            return ""
        }
        rrType := binary.BigEndian.Uint16(resp[offset+2 : offset+4])
        if rrType == 1 {
            rdLength := int(binary.BigEndian.Uint16(resp[offset+10 : offset+12]))
            rdata := resp[offset+12 : offset+12+rdLength]
            if len(rdata) == 4 {
                return net.IP(rdata).String()
            }
        }
        offset = skipRR(resp, offset)
        if offset == -1 {
            return ""
        }
    }
    return ""
}

