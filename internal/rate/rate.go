package rate

import (
	"sync"
	"time"
)

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
	return len(l.failures[key]) >= l.maxFailures
}

// RecordFailure records a failure for a key.
func (l *Limiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key)
	l.failures[key] = append(l.failures[key], time.Now())
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
