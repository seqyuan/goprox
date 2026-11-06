package files

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello")
	mustWrite(t, filepath.Join(root, "nested", "b.txt"), "world")
	mustWrite(t, filepath.Join(root, "nested", "deep", "c.txt"), "deep")
	mustWrite(t, filepath.Join(root, ".secret"), "hidden")
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func doRequest(t *testing.T, opts Options, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	Serve(rec, req, opts)
	return rec
}

func TestListingShowsEntriesAndHidesDotfiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root)
	rec := doRequest(t, Options{Root: root, RelPath: "/", LinkBase: "/proxy/alice/data", Name: "数据盘"}, "GET", "/data/")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"a.txt", "nested/", "empty/", "下载全部（ZIP）", `href="/proxy/alice/data/nested/"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing missing %q", want)
		}
	}
	if strings.Contains(body, ".secret</a>") {
		t.Error("hidden file must not be listed by default")
	}

	rec = doRequest(t, Options{Root: root, RelPath: "/", LinkBase: "/proxy/alice/data", Name: "数据盘", ShowHidden: true}, "GET", "/data/")
	if !strings.Contains(rec.Body.String(), ".secret</a>") {
		t.Error("show_hidden must list dotfiles")
	}
}

func TestListingLinksUnderBareRoot(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root)
	rec := doRequest(t, Options{Root: root, RelPath: "/nested", LinkBase: "", Name: "数据盘"}, "GET", "/nested/")
	body := rec.Body.String()
	// Bare-path (default_service / vhost) mounting: links stay at the host root.
	for _, want := range []string{`href="/nested/"`, `href="/"`, `href="/nested/deep/"`, `href="/nested/?zip=1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("bare-root listing missing %q in:\n%s", want, body)
		}
	}
}

func TestTraversalIsConfinedToRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "share")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(parent, "outside.txt"), "secret")

	for _, rel := range []string{"/../outside.txt", "/../../outside.txt", "/nested/../../../outside.txt"} {
		rec := doRequest(t, Options{Root: root, RelPath: rel, Name: "share"}, "GET", "/share"+rel)
		if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "secret") {
			t.Fatalf("rel=%q escaped the root: %s", rel, rec.Body.String())
		}
	}
}

func TestSymlinkEscapeIsRejected(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "share")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(parent, "outside.txt"), "secret")
	if err := os.Symlink(filepath.Join(parent, "outside.txt"), filepath.Join(root, "escape.txt")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	rec := doRequest(t, Options{Root: root, RelPath: "/escape.txt", Name: "share"}, "GET", "/share/escape.txt")
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("symlink escaped the root: %s", rec.Body.String())
	}
}

func TestFileServingHeaders(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root)

	// Inline, sandboxed text.
	rec := doRequest(t, Options{Root: root, RelPath: "/a.txt", Name: "share"}, "GET", "/a.txt")
	if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "inline") {
		t.Errorf("text should be inline, got %q", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "sandbox") {
		t.Errorf("inline body must be sandboxed, got %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("nosniff missing, got %q", got)
	}

	// Scriptable types are forced to download.
	htmlPath := filepath.Join(root, "page.html")
	mustWrite(t, htmlPath, "<script>alert(1)</script>")
	rec = doRequest(t, Options{Root: root, RelPath: "/page.html", Name: "share"}, "GET", "/page.html")
	if got := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(got, "attachment") {
		t.Errorf("html must download, got %q", got)
	}
	if got := rec.Header().Get("Content-Type"); strings.Contains(got, "html") {
		t.Errorf("html must not be served as html, got %q", got)
	}

	// Range requests must keep working (resumable downloads).
	req := httptest.NewRequest("GET", "/a.txt", nil)
	req.Header.Set("Range", "bytes=0-2")
	rec = httptest.NewRecorder()
	Serve(rec, req, Options{Root: root, RelPath: "/a.txt", Name: "share"})
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "hel" {
		t.Fatalf("range: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestZipDownloadContainsTree(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root)
	rec := doRequest(t, Options{Root: root, RelPath: "/nested", LinkBase: "/proxy/alice/data", Name: "数据盘"}, "GET", "/nested/?zip=1")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, `filename="nested.zip"`) {
		t.Fatalf("Content-Disposition = %q", got)
	}

	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(data)
	}
	want := map[string]string{
		"b.txt":      "world",
		"deep/c.txt": "deep",
		"deep/":      "",
	}
	for name, content := range want {
		if got[name] != content {
			t.Errorf("zip entry %q = %q, want %q (entries: %v)", name, got[name], content, keys(got))
		}
	}
}

func TestZipRootUsesServiceName(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root)
	rec := doRequest(t, Options{Root: root, RelPath: "/", Name: "数据盘"}, "GET", "/?zip=1")
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "filename*=UTF-8''%E6%95%B0%E6%8D%AE%E7%9B%98.zip") {
		t.Fatalf("Content-Disposition = %q", got)
	}
}

func TestOnlyGetAndHead(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root)
	rec := doRequest(t, Options{Root: root, RelPath: "/"}, "POST", "/")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q", got)
	}
}

func TestMissingFileIs404(t *testing.T) {
	root := t.TempDir()
	rec := doRequest(t, Options{Root: root, RelPath: "/nope.txt"}, "GET", "/nope.txt")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), root) {
		t.Fatal("error body must not echo the configured root")
	}
}

func TestUnreadableRootIs404(t *testing.T) {
	rec := doRequest(t, Options{Root: filepath.Join(t.TempDir(), "gone")}, "GET", "/")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, fmt.Sprintf("%q", k))
	}
	return out
}

// A non-ASCII name must not be emitted raw in a quoted-string: it gets an
// ASCII fallback plus an RFC 5987 filename*.
func TestContentDispositionEncodesNonASCII(t *testing.T) {
	got := contentDisposition("attachment", "数据盘.zip")
	if !strings.Contains(got, `filename="___.zip"`) {
		t.Errorf("missing ASCII fallback in %q", got)
	}
	if !strings.Contains(got, "filename*=UTF-8''%E6%95%B0%E6%8D%AE%E7%9B%98.zip") {
		t.Errorf("missing RFC 5987 filename* in %q", got)
	}

	root := t.TempDir()
	writeTree(t, root)
	rec := doRequest(t, Options{Root: root, RelPath: "/", Name: "数据盘"}, "GET", "/?zip=1")
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "filename*=UTF-8''") {
		t.Fatalf("zip Content-Disposition = %q", cd)
	}
}

// Zip export must not follow symlinks that escape the root, and must respect
// the hidden-file setting.
func TestZipSkipsEscapingSymlinksAndHidden(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "share")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "ok.txt"), "ok")
	mustWrite(t, filepath.Join(parent, "outside.txt"), "secret")
	mustWrite(t, filepath.Join(root, ".hidden", "h.txt"), "hidden")
	if err := os.Symlink(filepath.Join(parent, "outside.txt"), filepath.Join(root, "escape.txt")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	rec := doRequest(t, Options{Root: root, RelPath: "/", Name: "share"}, "GET", "/?zip=1")
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == "escape.txt" || strings.HasPrefix(f.Name, ".hidden") {
			t.Errorf("zip must not contain %q", f.Name)
		}
	}
}

// ?download=1 forces an attachment even for a previewable type.
func TestExplicitDownloadForcesAttachment(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root)
	rec := doRequest(t, Options{Root: root, RelPath: "/a.txt"}, "GET", "/a.txt?download=1")
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("download must not be typed as text, got %q", ct)
	}
}
