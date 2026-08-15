package rate

import (
	"context"
	"io"
	"time"

	"golang.org/x/time/rate"
)

// burstBytes is the token-bucket burst for bandwidth-limited streams. It must
// be at least as large as the largest single Read we ever issue, so a normal
// copy loop never waits for more tokens than the bucket can hold. The initial
// burst is spent on construction so a hard cap applies from the very first
// byte rather than letting the first burstBytes through at line speed.
const burstBytes = 1 << 20 // 1 MiB

// LimitedReader throttles reads from r to bytesPerSec (bytes per second).
// A non-positive limit disables throttling and reads directly from r.
// It implements io.ReadCloser so it can stand in for an http body.
type LimitedReader struct {
	r       io.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

// NewLimitedReader wraps r with a bandwidth cap. bytesPerSec <= 0 means
// unlimited.
func NewLimitedReader(r io.Reader, bytesPerSec int64) *LimitedReader {
	return NewLimitedReaderContext(r, bytesPerSec, context.Background())
}

// NewLimitedReaderContext is NewLimitedReader with an explicit context, used
// so a cancelled request/response aborts a blocked throttle wait promptly.
func NewLimitedReaderContext(r io.Reader, bytesPerSec int64, ctx context.Context) *LimitedReader {
	if ctx == nil {
		ctx = context.Background()
	}
	if bytesPerSec <= 0 {
		return &LimitedReader{r: r, ctx: ctx}
	}
	lr := &LimitedReader{
		r:       r,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSec), burstBytes),
		ctx:     ctx,
	}
	// Spend the initial burst so throttling begins immediately.
	lr.limiter.AllowN(time.Now(), burstBytes)
	return lr
}

func (lr *LimitedReader) Read(p []byte) (int, error) {
	if lr.limiter == nil {
		return lr.r.Read(p)
	}
	// Never request more than the bucket can hold in one shot; WaitN(n) with
	// n > burst would block forever.
	if len(p) > burstBytes {
		p = p[:burstBytes]
	}
	n, err := lr.r.Read(p)
	if n > 0 {
		if werr := lr.limiter.WaitN(lr.ctx, n); werr != nil {
			// The n bytes were already consumed; return them so the caller
			// (io.Copy) writes them before observing the error.
			return n, werr
		}
	}
	return n, err
}

// Close closes the underlying reader if it is closable.
func (lr *LimitedReader) Close() error {
	if c, ok := lr.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
