package main

import (
    "log"
    "net"
)

func main() {
    addr := ":53" // DNS port (requires admin privileges on Windows)
    conn, err := net.ListenPacket("udp", addr)
    if err != nil {
        log.Fatalf("Failed to bind: %v", err)
    }
    defer conn.Close()
    log.Printf("DNS Server listening on %s", addr)

    cache := NewCache()

    buf := make([]byte, 512)
    for {
        n, clientAddr, err := conn.ReadFrom(buf)
        if err != nil {
            log.Printf("Error reading: %v", err)
            continue
        }

        go handleDNSQuery(conn, clientAddr, buf[:n], cache)
    }
}

func handleDNSQuery(conn net.PacketConn, addr net.Addr, req []byte, cache *DNSCache) {
    _, question, err := parseDNSQuery(req)
    if err != nil {
        log.Printf("Bad DNS query: %v", err)
        return
    }

    domain := normalizeDomain(question.Name)
    log.Printf("Received query for: %s", domain)

    if resp, found := cache.Get(domain); found {
        log.Printf("Cache hit: %s", domain)
        conn.WriteTo(resp, addr)
        return
    }

    resp, err := forwardToUpstream(req)
    if err != nil {
        log.Printf("Failed to forward to upstream: %v", err)
        return
    }

    ttl := extractTTL(resp)
    cache.Set(domain, resp, ttl)
    log.Printf("Cache set: %s (TTL: %d)", domain, ttl)

    conn.WriteTo(resp, addr)
}

func forwardToUpstream(query []byte) ([]byte, error) {
    server := "8.8.8.8:53"
    conn, err := net.Dial("udp", server)
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    _, err = conn.Write(query)
    if err != nil {
        return nil, err
    }

    buf := make([]byte, 512)
    n, err := conn.Read(buf)
    if err != nil {
        return nil, err
    }
    return buf[:n], nil
}
