package main

import (
    "encoding/binary"
    "fmt"
    "strings"
)


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

func parseQName(data []byte, offset int) (string, int) {
    labels := []string{}
    for {
        if offset >= len(data) {
            return "", offset
        }
        length := int(data[offset])
        if length == 0 {
            offset++
            break
        }
        offset++
        if offset+length > len(data) {
            return "", offset
        }
        labels = append(labels, string(data[offset:offset+length]))
        offset += length
    }
    return strings.Join(labels, "."), offset
}
