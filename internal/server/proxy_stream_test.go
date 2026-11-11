package server

// 流式响应（SSE / 日志尾巴）必须逐块到达浏览器：访问日志的状态码包装不能把
// 它缓冲到响应结束。Jupyter、RStudio 的实时输出都走这条路。

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type streamChunk struct {
	line string
	err  error
}

// TestSSEStreamsIncrementallyThroughGateway proves the gateway forwards each
// event as it is produced, not when the backend finally closes the response.
// A backend is held open after the first event; if the gateway buffered it, the
// first read below would block until the release channel is closed.
func TestSSEStreamsIncrementallyThroughGateway(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "data: two\n\n")
		w.(http.Flusher).Flush()
	}))
	defer backend.Close()
	defer func() {
		// Never leave the backend handler blocked if the test fails early.
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	host, port := backendAddr(t, backend)
	srv := srvForBackend(t, host, port) // card: /jupyter -> that backend
	gw := httptest.NewServer(srv.Handler())
	defer gw.Close()

	req, err := http.NewRequest("GET", gw.URL+"/proxy/alice/jupyter/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", aliceSessionCookie())
	req.Header.Set("Accept", "text/event-stream")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content-type = %q", ct)
	}

	br := bufio.NewReader(resp.Body)
	// nextEvent reads the next non-blank line (event payload); the blank line
	// that terminates each SSE event is skipped.
	nextEvent := func() <-chan streamChunk {
		ch := make(chan streamChunk, 1)
		go func() {
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					ch <- streamChunk{"", err}
					return
				}
				if strings.TrimSpace(line) == "" {
					continue
				}
				ch <- streamChunk{line, nil}
				return
			}
		}()
		return ch
	}

	// First event must arrive while the backend is still holding the response.
	first := nextEvent()
	select {
	case c := <-first:
		if c.err != nil {
			t.Fatalf("first event read failed: %v", c.err)
		}
		if strings.TrimSpace(c.line) != "data: one" {
			t.Fatalf("first event = %q", c.line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first SSE event was buffered by the gateway (nothing arrived while the backend held the response)")
	}

	// Release the backend and expect the rest.
	close(release)
	second := nextEvent()
	select {
	case c := <-second:
		if c.err != nil {
			t.Fatalf("second event read failed: %v", c.err)
		}
		if strings.TrimSpace(c.line) != "data: two" {
			t.Fatalf("second event = %q", c.line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second SSE event never arrived after the backend finished")
	}

	// Drain to EOF so the gateway handler returns (the access record is written
	// after the response is finished), then check it is still one OK entry.
	if _, err := io.Copy(io.Discard, br); err != nil {
		t.Fatalf("drain failed: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		events := srv.events.List("alice", 0)
		if len(events) > 0 {
			if len(events) != 1 || events[0].Kind != "access" || !events[0].OK {
				t.Fatalf("events = %+v", events)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no access event recorded for the streamed request")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
