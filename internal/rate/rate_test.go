package rate

import (
	"fmt"
	"testing"
	"time"
)

// Keys that are never looked up again (e.g. attacker-flooded spoofed IPs)
// must not grow the failure map without bound.
func TestLimiterSweepsStaleKeys(t *testing.T) {
	l := NewLimiter(10, time.Hour)
	for i := 0; i < maxKeys+500; i++ {
		l.RecordFailure(fmt.Sprintf("spoofed-%d", i))
	}
	l.mu.Lock()
	size := len(l.failures)
	l.mu.Unlock()
	if size > maxKeys {
		t.Fatalf("map grew past cap: %d > %d", size, maxKeys)
	}

	// With a short window, flooding again after expiry must still keep the
	// map bounded (memory is the guarantee; lazy sweep triggers on growth).
	l2 := NewLimiter(10, 10*time.Millisecond)
	for i := 0; i < maxKeys+500; i++ {
		l2.RecordFailure(fmt.Sprintf("k-%d", i))
	}
	time.Sleep(30 * time.Millisecond)
	l2.RecordFailure("fresh")
	l2.RecordFailure("fresh2")
	l2.mu.Lock()
	size = len(l2.failures)
	l2.mu.Unlock()
	if size > maxKeys {
		t.Fatalf("map not bounded after expiry: %d entries", size)
	}
	// A fully-expired map under the threshold still gets reclaimed on demand.
	if _, ok := l2.failures["k-0"]; ok {
		// k-0 may or may not have been evicted; if present it must be treated
		// as stale and not count toward blocking.
		if l2.IsBlocked("k-0") {
			t.Fatal("stale key must not block")
		}
	}
}

// The blocking behavior itself must be unchanged.
func TestLimiterBlocksAfterMaxFailures(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		l.RecordFailure("ip")
	}
	if !l.IsBlocked("ip") {
		t.Fatal("expected blocked after max failures")
	}
	l.Reset("ip")
	if l.IsBlocked("ip") {
		t.Fatal("expected unblocked after reset")
	}
}

// Flooding many distinct keys must not evict a key that is currently blocked;
// otherwise an attacker could reset their own limit by creating noise keys.
func TestSweepKeepsBlockedKeys(t *testing.T) {
	l := NewLimiter(10, time.Hour)
	for i := 0; i < 10; i++ {
		l.RecordFailure("attacked")
	}
	for i := 0; i < maxKeys+500; i++ {
		l.RecordFailure(fmt.Sprintf("noise-%d", i))
	}
	if !l.IsBlocked("attacked") {
		t.Fatal("blocked key was evicted by the key-flood sweep")
	}
	l.mu.Lock()
	size := len(l.failures)
	l.mu.Unlock()
	if size > maxKeys {
		t.Fatalf("map grew past cap: %d > %d", size, maxKeys)
	}
}

// Under a saturated map (all existing keys blocked), the incoming key must
// still accumulate failures and become blocked; otherwise the per-key limit
// would silently stop working for every new key. One old block is evicted to
// make room (the documented hard-cap tradeoff).
func TestSweepAllowsNewKeyToBlockWhenSaturated(t *testing.T) {
	l := NewLimiter(2, time.Hour)
	l.capacity = 2

	for _, key := range []string{"a", "a", "b", "b"} {
		l.RecordFailure(key)
	}
	l.RecordFailure("c")
	if l.IsBlocked("c") {
		t.Fatal("c must not be blocked after one failure")
	}
	l.RecordFailure("c")
	if !l.IsBlocked("c") {
		t.Fatal("new key must be able to become blocked under saturation")
	}
	l.mu.Lock()
	size := len(l.failures)
	l.mu.Unlock()
	if size > l.capacity {
		t.Fatalf("map size = %d, cap = %d", size, l.capacity)
	}
}

// While there are unblocked keys, eviction must prefer them over a blocked
// key (the target of the attack).
func TestSweepEvictsUnblockedBeforeBlocked(t *testing.T) {
	l := NewLimiter(2, time.Hour)
	l.capacity = 2

	l.RecordFailure("attacked")
	l.RecordFailure("attacked")
	l.RecordFailure("noise")
	l.RecordFailure("incoming")

	if !l.IsBlocked("attacked") {
		t.Fatal("blocked key was evicted before unblocked noise")
	}
	if _, ok := l.failures["noise"]; ok {
		t.Fatal("unblocked noise key should have been evicted")
	}
	if _, ok := l.failures["incoming"]; !ok {
		t.Fatal("incoming protected key should have been kept")
	}
}
