package main

import "sync"

type Deduper struct {
	mu   sync.Mutex
	wait map[string]*sync.WaitGroup
}

func NewDeduper() *Deduper {
	return &Deduper{wait: make(map[string]*sync.WaitGroup)}
}

func (d *Deduper) Do(key string, fn func() ([]byte, error)) ([]byte, error) {
	d.mu.Lock()
	if wg, found := d.wait[key]; found {
		
		d.mu.Unlock()
		wg.Wait()
		return nil, nil 
	}

	
	wg := &sync.WaitGroup{}
	wg.Add(1)
	d.wait[key] = wg
	d.mu.Unlock()

	
	result, err := fn()

	
	d.mu.Lock()
	delete(d.wait, key)
	wg.Done()
	d.mu.Unlock()

	return result, err
}
