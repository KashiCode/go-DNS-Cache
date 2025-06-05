package main

import (
	"encoding/binary"
	"strings"
	"time"
)



func parseQName(b []byte, off int) (string, int) {
	var lbls []string
	for {
		if off >= len(b) {
			return "", off
		}
		l := int(b[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(b) {
			return "", off
		}
		lbls = append(lbls, string(b[off:off+l]))
		off += l
	}
	return strings.Join(lbls, "."), off
}

func normalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

func extractTTL(msg []byte) uint32 {
	
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	off := 12
	for i := 0; i < qd; i++ {
		_, off = parseQName(msg, off)
		off += 4
	}
	if off+4 > len(msg) {
		return 0
	}
	return binary.BigEndian.Uint32(msg[off+4 : off+8])
}



func extractCNAME(msg []byte) (string, bool) {
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	
	for i := 0; i < qd; i++ {
		off = skipQName(msg, off) + 4 
	}

	
	for i := 0; i < an; i++ {
		off = skipQName(msg, off)
		if off+8 > len(msg) {
			return "", false
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		off += 8                              
		rdLen := int(binary.BigEndian.Uint16(msg[off : off+2]))
		off += 2                              

		if typ == 5 { 
			target := extractName(msg, off)
			if target != "" {
				return target, true
			}
			return "", false
		}
		off += rdLen 
	}
	return "", false
}





func buildDNSQuery(name string, qtype, qclass uint16) []byte {
	id := uint16(time.Now().UnixNano() & 0xffff)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) 
	binary.BigEndian.PutUint16(hdr[4:6], 1)

	var qname []byte
	for _, lbl := range strings.Split(name, ".") {
		qname = append(qname, byte(len(lbl)))
		qname = append(qname, lbl...)
	}
	qname = append(qname, 0)

	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], qtype)
	binary.BigEndian.PutUint16(q[2:4], qclass)

	return append(append(hdr, qname...), q...)
}


func mergeDNSResponses(base, extra []byte) []byte {
	baseAn := binary.BigEndian.Uint16(base[6:8])
	extraAn := binary.BigEndian.Uint16(extra[6:8])

	
	qd := int(binary.BigEndian.Uint16(base[4:6]))
	off := 12
	for i := 0; i < qd; i++ {
		off = skipQName(base, off)
		off += 4
	}

	
	exOff := 12
	exQd := int(binary.BigEndian.Uint16(extra[4:6]))
	for i := 0; i < exQd; i++ {
		exOff = skipQName(extra, exOff)
		exOff += 4
	}

	merged := append(base, extra[exOff:]...)
	binary.BigEndian.PutUint16(merged[6:8], baseAn+extraAn)
	return merged
}



