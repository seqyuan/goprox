package rate

import (
	"sync"
	"time"
)

// maxKeys caps the failure map before a full sweep runs, bounding memory even
// if an attacker floods many distinct keys (e.g. spoofed forwarded IPs).
const maxKeys = 10000

// Limiter limits the rate of events per key.
type Limiter struct {
	maxFailures int
	window      time.Duration
	mu          sync.Mutex
	failures    map[string][]time.Time
}

// NewLimiter creates a rate limiter.
func NewLimiter(maxFailures int, window time.Duration) *Limiter {
	return &Limiter{
		maxFailures: maxFailures,
		window:      window,
		failures:    make(map[string][]time.Time),
	}
}

// IsBlocked checks if a key is currently blocked.
func (l *Limiter) IsBlocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key)
	l.sweepIfLarge()
	return len(l.failures[key]) >= l.maxFailures
}

// RecordFailure records a failure for a key.
func (l *Limiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key)
	l.failures[key] = append(l.failures[key], time.Now())
	l.sweepIfLarge()
}

// Reset clears failures for a key.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func (l *Limiter) prune(key string) {
	cutoff := time.Now().Add(-l.window)
	times := l.failures[key]
	if len(times) == 0 {
		return
	}
	filtered := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) == 0 {
		delete(l.failures, key)
	} else {
		l.failures[key] = filtered
	}
}

// sweepIfLarge removes expired entries for every key once the map grows past
// maxKeys, then evicts arbitrary entries if the map is still over the cap
// (flooded keys that are never looked up again cannot be reclaimed by per-key
// pruning; eviction bounds memory while live keys re-accumulate on the next
// failure).
func (l *Limiter) sweepIfLarge() {
	if len(l.failures) <= maxKeys {
		return
	}
	cutoff := time.Now().Add(-l.window)
	for k := range l.failures {
		times := l.failures[k]
		filtered := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			delete(l.failures, k)
		} else {
			l.failures[k] = filtered
		}
	}
	// Hard cap: Go map iteration is randomized, so eviction is fair-ish.
	excess := len(l.failures) - maxKeys
	for k := range l.failures {
		if excess <= 0 {
			break
		}
		delete(l.failures, k)
		excess--
	}
}
