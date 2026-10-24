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
	capacity    int // failure-map hard cap (maxKeys, overridable in tests)
	window      time.Duration
	mu          sync.Mutex
	failures    map[string][]time.Time
}

// NewLimiter creates a rate limiter.
func NewLimiter(maxFailures int, window time.Duration) *Limiter {
	return &Limiter{
		maxFailures: maxFailures,
		capacity:    maxKeys,
		window:      window,
		failures:    make(map[string][]time.Time),
	}
}

// IsBlocked checks if a key is currently blocked.
func (l *Limiter) IsBlocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key)
	l.sweepIfLarge(key)
	return len(l.failures[key]) >= l.maxFailures
}

// RecordFailure records a failure for a key.
func (l *Limiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key)
	l.failures[key] = append(l.failures[key], time.Now())
	l.sweepIfLarge(key)
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
// capacity, then evicts entries if the map is still over the cap. protectKey
// (the key being checked/recorded) is never evicted: under a saturated map,
// dropping the incoming key would prevent it from ever accumulating failures,
// silently disabling the per-key limit. Instead an existing blocked key is
// evicted to make room, so new keys still become blocked (at the cost of one
// old block under an extreme all-blocked flood).
func (l *Limiter) sweepIfLarge(protectKey string) {
	if len(l.failures) <= l.capacity {
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
	// Hard cap. Prefer evicting unblocked keys: an attacker flooding cheap
	// distinct keys must not reset the limit of the key being attacked.
	excess := len(l.failures) - l.capacity
	for k, times := range l.failures {
		if excess <= 0 {
			break
		}
		if k == protectKey || len(times) >= l.maxFailures {
			continue
		}
		delete(l.failures, k)
		excess--
	}
	// All remaining unblocked keys (if any) were the protected incoming key,
	// or every key is blocked. Evict a blocked key other than the protected
	// one so the incoming key can still reach the failure threshold.
	for k := range l.failures {
		if excess <= 0 {
			break
		}
		if k == protectKey {
			continue
		}
		delete(l.failures, k)
		excess--
	}
	// Degenerate case: the protected key is the only entry (e.g. capacity 0
	// or a tiny test limiter). Drop it rather than growing past the cap.
	for k := range l.failures {
		if excess <= 0 {
			break
		}
		delete(l.failures, k)
		excess--
	}
}
