package rate

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// A non-positive limit must disable throttling entirely.
func TestLimitedReaderUnlimited(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4096)
	lr := NewLimitedReader(bytes.NewReader(payload), 0)
	if lr.limiter != nil {
		t.Fatal("unlimited reader must not carry a limiter")
	}
	got, err := io.ReadAll(lr)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payload) {
		t.Fatalf("unlimited reader altered payload: %d != %d", len(got), len(payload))
	}
}

// The initial burst must be spent so a hard cap applies from byte one, not
// only after the first burstBytes stream through at line speed.
func TestLimitedReaderSpendsInitialBurst(t *testing.T) {
	lr := NewLimitedReader(bytes.NewReader(nil), 1024)
	if lr.limiter.Allow() {
		t.Fatal("initial burst must already be spent")
	}
}

// A limited reader must actually throttle: reading N bytes at R bytes/sec
// cannot finish faster than roughly N/R seconds.
func TestLimitedReaderThrottles(t *testing.T) {
	const (
		rate     = int64(512 * 1024) // 512 KiB/s
		payloadN = 512 * 1024        // 512 KiB => ~1s at the cap
	)
	payload := bytes.Repeat([]byte("a"), payloadN)

	start := time.Now()
	got, err := io.ReadAll(NewLimitedReader(bytes.NewReader(payload), rate))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != payloadN {
		t.Fatalf("payload altered: %d != %d", len(got), payloadN)
	}

	min := time.Duration(float64(payloadN) / float64(rate) * float64(time.Second) * 0.5)
	if elapsed < min {
		t.Fatalf("throttle ineffective: %d bytes at %d B/s took %v (expected >= %v)", payloadN, rate, elapsed, min)
	}
	// Generous upper bound guards against CI stall flakes, not against a real
	// bug: any sane run stays far below this.
	if elapsed > 15*time.Second {
		t.Fatalf("throttle too slow: %v", elapsed)
	}
}

// Reading with a buffer larger than the bucket must cap the request and still
// make progress (WaitN(n) with n > burst would otherwise block forever).
func TestLimitedReaderCapsOversizedRead(t *testing.T) {
	payload := bytes.Repeat([]byte("b"), 2*burstBytes+1)
	lr := NewLimitedReader(bytes.NewReader(payload), int64(burstBytes)*2)

	big := make([]byte, 2*burstBytes+1)
	n, err := lr.Read(big)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("oversized read must return data")
	}
	if n > burstBytes {
		t.Fatalf("read exceeded the bucket cap: %d > %d", n, burstBytes)
	}
}
