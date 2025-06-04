package main

import (
	"encoding/binary"
	"fmt"
	//"log"
	"net"
	"time"
)


var rootServers = []string{
	"198.41.0.4:53",   
	"199.7.91.13:53",  
	"192.5.5.241:53",  
	"192.203.230.10:53",
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

func parseDNSQuery(b []byte) (DNSHeader, DNSQuestion, error) {
	if len(b) < 12 {
		return DNSHeader{}, DNSQuestion{}, fmt.Errorf("truncated header")
	}
	h := DNSHeader{
		ID:      binary.BigEndian.Uint16(b[0:2]),
		Flags:   binary.BigEndian.Uint16(b[2:4]),
		QDCount: binary.BigEndian.Uint16(b[4:6]),
		ANCount: binary.BigEndian.Uint16(b[6:8]),
		NSCount: binary.BigEndian.Uint16(b[8:10]),
		ARCount: binary.BigEndian.Uint16(b[10:12]),
	}
	name, off := parseQName(b, 12)
	if off+4 > len(b) {
		return h, DNSQuestion{}, fmt.Errorf("truncated question")
	}
	q := DNSQuestion{
		Name:  name,
		Type:  binary.BigEndian.Uint16(b[off : off+2]),
		Class: binary.BigEndian.Uint16(b[off+2 : off+4]),
	}
	return h, q, nil
}



func resolveRecursively(q []byte) ([]byte, error) {
	servers := append([]string(nil), rootServers...)
	for depth := 0; depth < 15; depth++ {
		var lastErr error
		for _, srv := range servers {
			conn, err := net.Dial("udp", srv)
			if err != nil {
				lastErr = err
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = conn.Write(q); err != nil {
				lastErr = err
				conn.Close()
				continue
			}
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			conn.Close()
			if err != nil {
				lastErr = err
				continue
			}
			resp := buf[:n]
			if binary.BigEndian.Uint16(resp[6:8]) > 0 { 
				return resp, nil
			}

			glue, ns := extractNextServers(resp)
			if len(glue) == 0 && len(ns) == 0 {
				return resp, nil 
			}

			if len(glue) == 0 { 
				for _, n := range ns {
					nq := buildDNSQuery(n, 1, 1)
					r, err := resolveRecursively(nq)
					if err != nil {
						continue
					}
					if ip := extractARecord(r); ip != "" {
						glue = append(glue, ip+":53")
					}
				}
			}
			if len(glue) > 0 {
				servers = glue
				break 
			}
		}
		if servers == nil {
			return nil, lastErr
		}
	}
	return nil, fmt.Errorf("max recursion depth reached")
}



func extractNextServers(resp []byte) (ips, names []string) {
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	ns := int(binary.BigEndian.Uint16(resp[8:10]))
	ar := int(binary.BigEndian.Uint16(resp[10:12]))

	off := 12
	for i := 0; i < qd; i++ {
		off = skipQName(resp, off) + 4
	}
	for i := 0; i < an; i++ {
		off = skipRR(resp, off)
	}
	for i := 0; i < ns; i++ {
		start := off
		off = skipRR(resp, off)
		if start+12 > len(resp) {
			continue
		}
		if binary.BigEndian.Uint16(resp[start+2:start+4]) == 2 { // NS
			if n := extractName(resp, start+12); n != "" {
				names = append(names, n)
			}
		}
	}
	for i := 0; i < ar; i++ {
		start := off
		off = skipRR(resp, off)
		if start+12 > len(resp) {
			continue
		}
		if binary.BigEndian.Uint16(resp[start+2:start+4]) == 1 { // A
			l := int(binary.BigEndian.Uint16(resp[start+10 : start+12]))
			if start+12+l <= len(resp) {
				ips = append(ips, net.IP(resp[start+12:start+12+l]).String()+":53")
			}
		}
	}
	return
}

func skipRR(b []byte, off int) int {
	off = skipQName(b, off)
	if off+10 > len(b) {
		return len(b)
	}
	l := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
	return off + 10 + l
}

func skipQName(b []byte, off int) int {
	for {
		if off >= len(b) {
			return len(b)
		}
		l := int(b[off])
		if l == 0 {
			return off + 1
		}
		if l&0xc0 == 0xc0 { 
			return off + 2
		}
		off += l + 1
	}
}

func extractName(b []byte, off int) string {
	var out string
	for {
		if off >= len(b) {
			return ""
		}
		l := int(b[off])
		if l&0xc0 == 0xc0 {
			ptr := int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff)
			return out + extractName(b, ptr)
		}
		if l == 0 {
			break
		}
		off++
		if off+l > len(b) {
			return ""
		}
		if out != "" {
			out += "."
		}
		out += string(b[off : off+l])
		off += l
	}
	return out
}

func extractARecord(msg []byte) string {
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	off := 12
	for i := 0; i < qd; i++ {
		off = skipQName(msg, off) + 4
	}
	for off+12 <= len(msg) {
		if binary.BigEndian.Uint16(msg[off+2:off+4]) == 1 {
			l := int(binary.BigEndian.Uint16(msg[off+10 : off+12]))
			if off+12+l <= len(msg) {
				return net.IP(msg[off+12 : off+12+l]).String()
			}
		}
		off = skipRR(msg, off)
	}
	return ""
}
