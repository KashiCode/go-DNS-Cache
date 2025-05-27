package main

import (
    "log"
    "net"
    "fmt"
)

func main() {
    addr := ":53" // DNS port (Use powershell admin)
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
    _, question, err := parseDNSQuery(req) //update to header to access. 
    if err != nil {
        log.Printf("Bad DNS query: %v", err)
        return
    }

    recordType := map[uint16]string{
        1:  "A",
        28: "AAAA",
        15: "MX",
        5:  "CNAME",
        12: "PTR",
    }

    rtypeName, ok := recordType[question.Type]
    if !ok {
        rtypeName = fmt.Sprintf("TYPE%d", question.Type)
    }

    domain := normalizeDomain(question.Name)
    key := fmt.Sprintf("%s:%d", domain, question.Type)

    log.Printf("Received query for: %s (%s)", domain, rtypeName)

    
    if resp, found := cache.Get(key); found {
        log.Printf("Cache hit: %s (%s)", domain, rtypeName)
        conn.WriteTo(resp, addr)
        return
    }

    
    resp, err := forwardToUpstream(req)
    if err != nil {
        log.Printf("Forward failed: %v", err)
        return
    }

    ttl := extractTTL(resp)
    cache.Set(key, resp, ttl)
    log.Printf("Cache set: %s (%s) (TTL: %d)", domain, rtypeName, ttl)

    
    cname, ok := extractCNAME(resp)
    if ok {
        cname = normalizeDomain(cname)
        cnameKey := fmt.Sprintf("%s:%d", cname, question.Type)

        
        if finalResp, found := cache.Get(cnameKey); found {
            log.Printf("CNAME follow cache hit: %s", cname)
            merged := mergeDNSResponses(resp, finalResp)
            conn.WriteTo(merged, addr)
            return
        }

        log.Printf("CNAME follow: querying %s", cname)
        cnameQuery := buildDNSQuery(cname, question.Type, question.Class)
        cnameResp, err := forwardToUpstream(cnameQuery)
        if err == nil {
            ttl := extractTTL(cnameResp)
            cache.Set(cnameKey, cnameResp, ttl)
            log.Printf("Cache set: %s (CNAME target) (TTL: %d)", cname, ttl)
        }
    }

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
