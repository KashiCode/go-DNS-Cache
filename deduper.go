package main

import "sync"

// Deduper collapses duplicate in-flight queries so that only one dial to
// upstream resolvers is active per <name:type> key.
type Deduper struct {
	mu   sync.Mutex
	wait map[string]*sync.WaitGroup
}

func NewDeduper() *Deduper { return &Deduper{wait: map[string]*sync.WaitGroup{}} }

func (d *Deduper) Do(key string, fn func() ([]byte, error)) ([]byte, error) {
	d.mu.Lock()
	if wg, ok := d.wait[key]; ok {
		d.mu.Unlock()
		wg.Wait()           // someone else is working
		return nil, nil     // caller will retry cache after wait
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	d.wait[key] = wg
	d.mu.Unlock()

	
	res, err := fn()

	d.mu.Lock()
	delete(d.wait, key)
	wg.Done()
	d.mu.Unlock()

	return res, err
}
