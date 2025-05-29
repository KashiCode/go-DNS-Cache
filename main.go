package main

import (
    "encoding/binary"
    "fmt"
    "log"
    "net"
)

func main() {
    cache := NewCache()
    deduper := NewDeduper()

    go startTCPServer(cache,deduper) // Start TCP listener
    startUDPServer(cache,deduper)    // Start UDP listener 
}


func startUDPServer(cache *DNSCache, deduper *Deduper) {
    conn, err := net.ListenPacket("udp", "0.0.0.0:8053")
    if err != nil {
        log.Fatalf("UDP bind failed: %v", err)
    }
    defer conn.Close()
    log.Println("UDP DNS server listening on :8053")

    buf := make([]byte, 512)
    for {
        n, addr, err := conn.ReadFrom(buf)
        if err != nil {
            log.Printf("UDP read error: %v", err)
            continue
        }
        go handleDNSQuery(conn, addr, buf[:n], cache, deduper)
    }
}


func startTCPServer(cache *DNSCache, deduper *Deduper) {
    ln, err := net.Listen("tcp", "0.0.0.0:8053")
    if err != nil {
        log.Fatalf("Failed to start TCP server: %v", err)
    }
    log.Println("TCP DNS server listening on :8053")

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("Failed to accept TCP connection: %v", err)
            continue
        }
        go handleTCPConnection(conn, cache, deduper)
    }
}


func handleTCPConnection(conn net.Conn, cache *DNSCache, deduper *Deduper) {
    defer conn.Close()

    lengthBuf := make([]byte, 2)
    _, err := conn.Read(lengthBuf)
    if err != nil {
        log.Printf("TCP read (length) error: %v", err)
        return
    }

    length := binary.BigEndian.Uint16(lengthBuf)
    if length == 0 || length > 4096 {
        log.Printf("TCP length too large or invalid: %d", length)
        return
    }

    data := make([]byte, length)
    _, err = conn.Read(data)
    if err != nil {
        log.Printf("TCP read (data) error: %v", err)
        return
    }

    response := handleDNSQueryTCP(data, cache, deduper)
    if response == nil {
        return 
    }

    respLen := make([]byte, 2)
    binary.BigEndian.PutUint16(respLen, uint16(len(response)))
    conn.Write(append(respLen, response...))
}

//Handles DNS Query (dig)
func handleDNSQueryTCP(req []byte, cache *DNSCache, deduper *Deduper) []byte {
    _, question, err := parseDNSQuery(req)
    if err != nil {
        log.Printf("Bad DNS TCP query: %v", err)
        return nil
    }

    rtype := fmt.Sprintf("TYPE%d", question.Type)
    domain := normalizeDomain(question.Name)
    key := fmt.Sprintf("%s:%d", domain, question.Type)

    log.Printf("TCP: Received query for: %s (%s)", domain, rtype)

    if resp, found := cache.Get(key); found {
        log.Printf("TCP: Cache hit: %s (%s)", domain, rtype)
        
        fixedResp := make([]byte, len(resp))
        copy(fixedResp, resp)
        copy(fixedResp[0:2], req[0:2]) // overwrite transaction ID
        return fixedResp
    }

    resp, err := deduper.Do(key, func() ([]byte, error) {
    return forwardToUpstream(req)
    })
    if err != nil {
        log.Printf("TCP: Forward failed: %v", err)
        return nil
    }

    if resp == nil {
        return nil
    }
    
    copy(resp[0:2], req[0:2]) 

    ttl := extractTTL(resp)
    cache.Set(key, resp, ttl)
    log.Printf("TCP: Cache set: %s (%s) (TTL: %d)", domain, rtype, ttl)

    return resp
}


func handleDNSQuery(conn net.PacketConn, addr net.Addr, req []byte, cache *DNSCache, deduper *Deduper) {
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
        2:  "NS",
        16: "TXT",
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

    resp, err := deduper.Do(key, func() ([]byte, error) {
    return forwardToUpstream(req)
    })
    if err != nil {
        log.Printf("Forward failed: %v", err)
        return
    }
    if resp == nil {
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