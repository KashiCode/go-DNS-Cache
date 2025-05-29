package main

import (
    "sync"
    "time"
)

type CacheEntry struct {
    Data      []byte
    ExpiresAt time.Time
}


type DNSCache struct {
    mu      sync.Mutex
    entries map[string]CacheEntry
}


func NewCache() *DNSCache {
    return &DNSCache{
        entries: make(map[string]CacheEntry),
    }
}


func (c *DNSCache) Get(key string) ([]byte, bool) {
    c.mu.Lock()
    defer c.mu.Unlock()

    entry, found := c.entries[key]
    if !found || time.Now().After(entry.ExpiresAt) {
        delete(c.entries, key)
        return nil, false
    }
    return entry.Data, true
}


func (c *DNSCache) Set(key string, data []byte, ttl uint32) {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.entries[key] = CacheEntry{
        Data:      data,
        ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
    }
}

func (c *DNSCache) StartEvictionLoop(interval time.Duration) {
    go func() {
        for {
            time.Sleep(interval)
            c.mu.Lock()
            now := time.Now()
            for key, entry := range c.entries {
                if now.After(entry.ExpiresAt) {
                    delete(c.entries, key)
                }
            }
            c.mu.Unlock()
        }
    }()
}

