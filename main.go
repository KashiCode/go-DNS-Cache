package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

const listenAddr = "0.0.0.0:8053"

func main() {
	cache   := NewCache()
	deduper := NewDeduper()
	cache.StartEvictionLoop(30 * time.Second)

	log.Printf("Recursive DNS server listening on %s (UDP+TCP)", listenAddr)
	go tcpListener(cache, deduper)
	udpListener(cache, deduper)
}



func udpListener(cache *DNSCache, d *Deduper) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		log.Fatalf("UDP bind error: %v", err)
	}
	defer pc.Close()

	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		req := append([]byte(nil), buf[:n]...) 
		go func() {
			resp := handleQuery(req, cache, d)
			if resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}()
	}
}



func tcpListener(cache *DNSCache, d *Deduper) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("TCP listen error: %v", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go tcpServe(conn, cache, d)
	}
}

func tcpServe(c net.Conn, cache *DNSCache, d *Deduper) {
	defer c.Close()

	lenBuf := make([]byte, 2)
	if _, err := c.Read(lenBuf); err != nil {
		return
	}
	l := binary.BigEndian.Uint16(lenBuf)
	req := make([]byte, l)
	if _, err := c.Read(req); err != nil {
		return
	}

    log.Printf("TCP query %d bytes from %s", l, c.RemoteAddr())

	resp := handleQuery(req, cache, d)
	if resp == nil {
		return
	}
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(len(resp)))
	_, _ = c.Write(append(out, resp...))
}


func handleQuery(req []byte, cache *DNSCache, d *Deduper) []byte {
	start := time.Now()

	
	_, q, err := parseDNSQuery(req)
	if err != nil {
		return nil
	}
	key := fmt.Sprintf("%s:%d", normalizeDomain(q.Name), q.Type)

	
	if resp, ok := cache.Get(key); ok {
		reply := patchHeader(resp, req)
		log.Printf("CACHE  %s  type %d  %v", q.Name, q.Type, time.Since(start))
		return reply
	}

	
	resp, err := d.Do(key, func() ([]byte, error) {
		return resolveRecursively(req)
	})
	if err != nil {
		log.Printf("FAIL   %s  type %d  %v  (err=%v)", q.Name, q.Type, time.Since(start), err)
		return nil
	}

	
	if resp == nil {
		if cached, ok := cache.Get(key); ok {
			reply := patchHeader(cached, req)
			log.Printf("CACHE  %s  type %d  %v  (post-dedupe)", q.Name, q.Type, time.Since(start))
			return reply
		}
		log.Printf("FAIL   %s  type %d  %v  (pioneer miss)", q.Name, q.Type, time.Since(start))
		return nil
	}

	
	cache.Set(key, resp, extractTTL(resp))
	reply := patchHeader(resp, req)
	log.Printf("ANS    %s  type %d  %v", q.Name, q.Type, time.Since(start))

	
	if cn, ok := extractCNAME(resp); ok {
		cnKey := fmt.Sprintf("%s:%d", normalizeDomain(cn), q.Type)
		if end, ok := cache.Get(cnKey); ok {
			log.Printf("CNAME  %s → %s  type %d  %v (cache)", q.Name, cn, q.Type, time.Since(start))
			return mergeDNSResponses(reply, end)
		}
		end, err := resolveRecursively(buildDNSQuery(cn, q.Type, q.Class))
		if err == nil {
			cache.Set(cnKey, end, extractTTL(end))
			log.Printf("CNAME  %s → %s  type %d  %v", q.Name, cn, q.Type, time.Since(start))
			return mergeDNSResponses(reply, end)
		}
	}

	return reply
}

