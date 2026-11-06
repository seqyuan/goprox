// Package files serves a read-only browser over a local directory tree for
// services of kind "files": the gateway plays the backend itself, so a card can
// be "this directory on this machine" instead of a host:port that has to be run
// and watched separately.
//
// Everything is read-only: no upload, delete, rename or write path exists.
package files

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"

	"github.com/seqyuan/goprox/internal/rate"
	"github.com/seqyuan/goprox/internal/web"
)

// maxZipDepth bounds directory recursion in a zip download so a symlink cycle
// (or an absurdly deep tree) cannot spin forever. os.Root already refuses
// escaping symlinks; this is a belt-and-braces bound.
const maxZipDepth = 64

// Options describes one request against a directory service.
type Options struct {
	// Root is the absolute directory the service exposes.
	Root string
	// RelPath is the browser path relative to the service root (may carry a
	// leading slash). It is cleaned here, never trusted as a filesystem path.
	RelPath string
	// LinkBase is the browser-visible URL prefix the service is mounted at
	// ("/proxy/<user>/<svc>" in path mode, "" for vhost / bare-path routing).
	LinkBase string
	// ShowHidden lists dotfiles (off by default: .git, .env and friends are not
	// something a file browser should advertise).
	ShowHidden bool
	// Name labels the page and the zip download (the service name).
	Name string
	// BWLimit caps the delivered bytes per second (0 = unlimited).
	BWLimit int64
}

// Serve answers a GET/HEAD request for a directory service.
func Serve(w http.ResponseWriter, r *http.Request, opts Options) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rel, ok := cleanRelPath(opts.RelPath)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	root, err := os.OpenRoot(opts.Root)
	if err != nil {
		// The directory disappeared or is unreadable: answer 404 rather than
		// leaking the configured absolute path to the browser.
		http.Error(w, "directory unavailable", http.StatusNotFound)
		return
	}
	defer root.Close()

	fsPath := relToFSPath(rel)
	info, err := root.Stat(fsPath)
	if err != nil {
		writeFSError(w, err)
		return
	}

	switch {
	case info.IsDir() && wantsZip(r):
		serveZip(w, r, root, fsPath, rel, opts)
	case info.IsDir():
		serveListing(w, r, root, fsPath, rel, opts)
	case info.Mode().IsRegular():
		serveFile(w, r, root, fsPath, info, opts)
	default:
		http.Error(w, "not a regular file", http.StatusForbidden)
	}
}

// wantsZip reports whether the request asks for the directory as a zip
// archive. ?download=1 on a directory means the same thing.
func wantsZip(r *http.Request) bool {
	q := r.URL.Query()
	return q.Has("zip") || q.Has("download")
}

// cleanRelPath validates and canonicalizes the browser path. Control characters
// are rejected outright: they are never legitimate in a path.
func cleanRelPath(p string) (string, bool) {
	for _, c := range p {
		if c == 0 || c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	// path.Clean on an absolute path collapses ".." without walking above the
	// root; os.Root rejects any remaining attempt to escape.
	return pathpkg.Clean("/" + strings.TrimPrefix(p, "/")), true
}

// relToFSPath converts a cleaned slash path to the name os.Root expects ("."
// addresses the root itself).
func relToFSPath(rel string) string {
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "."
	}
	return rel
}

// linkFor builds the browser URL for a path relative to the service root.
func linkFor(linkBase, rel string, isDir bool) string {
	base := strings.TrimSuffix(linkBase, "/")
	clean := pathpkg.Clean("/" + strings.TrimPrefix(rel, "/"))
	if clean == "/" {
		if base == "" {
			return "/"
		}
		return base + "/"
	}
	var b strings.Builder
	b.WriteString(base)
	for _, seg := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		b.WriteString("/")
		b.WriteString(url.PathEscape(seg))
	}
	if isDir {
		b.WriteString("/")
	}
	return b.String()
}

type entry struct {
	name  string
	href  string
	isDir bool
	size  string
	kind  string
	mtime string
}

func serveListing(w http.ResponseWriter, r *http.Request, root *os.Root, fsPath, rel string, opts Options) {
	entries, err := readDir(root, fsPath)
	if err != nil {
		writeFSError(w, err)
		return
	}

	rows := make([]entry, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !opts.ShowHidden && strings.HasPrefix(name, ".") {
			continue
		}
		// Stat each entry to resolve symlinks and obtain sizes. An entry that
		// cannot be resolved (dangling or root-escaping symlink) is skipped.
		info, err := root.Stat(pathpkg.Join(fsPath, name))
		if err != nil {
			continue
		}
		row := entry{
			name:  name,
			isDir: info.IsDir(),
			href:  linkFor(opts.LinkBase, pathpkg.Join(rel, name), info.IsDir()),
			kind:  "文件",
			mtime: info.ModTime().Format("2006-01-02 15:04"),
		}
		switch {
		case info.IsDir():
			row.kind = "目录"
		case info.Mode()&os.ModeSymlink != 0:
			row.kind = "链接"
		case !info.Mode().IsRegular():
			row.kind = "特殊"
		default:
			row.size = humanSize(info.Size())
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].isDir != rows[j].isDir {
			return rows[i].isDir
		}
		return strings.ToLower(rows[i].name) < strings.ToLower(rows[j].name)
	})

	title := pathpkg.Base(rel)
	if rel == "/" {
		title = opts.Name
	}

	var body strings.Builder
	body.WriteString(listingStyle)
	body.WriteString(`<div class="gf-wrap"><div class="gf-card">`)
	fmt.Fprintf(&body, `<h1>%s</h1>`, html.EscapeString(title))
	fmt.Fprintf(&body, `<p class="gf-meta">%s · 只读浏览 · 共 %d 项</p>`, html.EscapeString(opts.Name), len(rows))
	body.WriteString(`<div class="gf-actions">`)
	fmt.Fprintf(&body, `<a class="gf-btn" href="%s?zip=1">下载全部（ZIP）</a>`,
		html.EscapeString(linkFor(opts.LinkBase, rel, true)))
	if rel != "/" {
		fmt.Fprintf(&body, `<a class="gf-btn gf-secondary" href="%s">上一级</a>`,
			html.EscapeString(linkFor(opts.LinkBase, pathpkg.Dir(rel), true)))
	}
	body.WriteString(`</div><p class="gf-crumbs">`)
	fmt.Fprintf(&body, `<a href="%s">根目录</a>`, html.EscapeString(linkFor(opts.LinkBase, "/", true)))
	acc := "/"
	for _, seg := range strings.Split(strings.TrimPrefix(rel, "/"), "/") {
		if seg == "" {
			continue
		}
		acc = pathpkg.Join(acc, seg)
		fmt.Fprintf(&body, ` / <a href="%s">%s</a>`,
			html.EscapeString(linkFor(opts.LinkBase, acc, true)), html.EscapeString(seg))
	}
	body.WriteString(`</p>`)

	if len(rows) == 0 {
		body.WriteString(`<p class="gf-empty">空目录（或所有条目都被隐藏）。</p>`)
	} else {
		body.WriteString(`<table class="gf-table"><thead><tr><th>名称</th><th class="gf-num">大小</th><th>类型</th><th>修改时间</th></tr></thead><tbody>`)
		for _, row := range rows {
			label := html.EscapeString(row.name)
			if row.isDir {
				label += "/"
			}
			fmt.Fprintf(&body, `<tr><td><a href="%s">%s</a></td><td class="gf-num">%s</td><td class="gf-muted">%s</td><td class="gf-muted">%s</td></tr>`,
				html.EscapeString(row.href), label, row.size, row.kind, row.mtime)
		}
		body.WriteString(`</tbody></table>`)
	}
	body.WriteString(`</div></div>`)

	page := web.PageShell(opts.Name, title, body.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	// Fully server-rendered: no script, no external resources.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.Header().Set("Content-Length", strconv.Itoa(len(page)))
	if r.Method == http.MethodHead {
		return
	}
	io.WriteString(w, page)
}

const listingStyle = `<style>
.gf-wrap{max-width:960px;margin:32px auto;padding:0 16px}
.gf-card{background:var(--bg-panel,#fff);border:1px solid var(--border,#e2e8f0);border-radius:14px;padding:20px 22px}
.gf-card h1{font-size:19px;margin:0 0 4px}
.gf-meta{margin:0 0 14px;color:var(--text-muted,#64748b);font-size:13px}
.gf-actions{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.gf-btn{display:inline-block;padding:6px 12px;border-radius:8px;border:1px solid var(--border,#e2e8f0);background:var(--accent,#3b6ef5);color:#fff;text-decoration:none;font-size:13px}
.gf-secondary{background:transparent;color:var(--text,#1e293b)}
.gf-crumbs{font-size:13px;color:var(--text-muted,#64748b);margin:0 0 12px;word-break:break-all}
.gf-crumbs a{color:inherit}
.gf-table{width:100%;border-collapse:collapse;font-size:13.5px}
.gf-table th,.gf-table td{padding:7px 10px;border-bottom:1px solid var(--border,#e2e8f0);text-align:left}
.gf-table th{font-weight:600;color:var(--text-muted,#64748b);font-size:12px}
.gf-table a{text-decoration:none;color:var(--accent,#3b6ef5)}
.gf-num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.gf-muted{color:var(--text-muted,#64748b);white-space:nowrap}
.gf-empty{color:var(--text-muted,#64748b);font-size:13px}
</style>`

// readDir lists a directory through the root.
func readDir(root *os.Root, fsPath string) ([]fs.DirEntry, error) {
	f, err := root.Open(fsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

func serveFile(w http.ResponseWriter, r *http.Request, root *os.Root, fsPath string, info os.FileInfo, opts Options) {
	f, err := root.Open(fsPath)
	if err != nil {
		writeFSError(w, err)
		return
	}
	defer f.Close()

	name := pathpkg.Base(fsPath)
	ctype, inline := inlineContentType(name)
	if r.URL.Query().Has("download") {
		// An explicit download link always wins over inline preview.
		inline = false
	}

	hdr := w.Header()
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Cache-Control", "private, max-age=0, must-revalidate")
	if inline {
		hdr.Set("Content-Type", ctype)
		// Even a "safe" type is served from the gateway origin, so sandbox it:
		// HTML/SVG disguised behind a text extension must not be able to script
		// against the gateway's session.
		hdr.Set("Content-Security-Policy", "sandbox; default-src 'none'")
		hdr.Set("Content-Disposition", contentDisposition("inline", name))
	} else {
		// ServeContent would otherwise re-derive a Content-Type from the
		// extension (text/html for a .html file). Force an opaque type: the
		// body is a download, never a document in this origin.
		hdr.Set("Content-Type", "application/octet-stream")
		hdr.Set("Content-Disposition", contentDisposition("attachment", name))
	}

	var rs io.ReadSeeker = f
	if opts.BWLimit > 0 {
		rs = &limitedReadSeeker{rs: f, lim: rate.NewLimitedReaderContext(f, opts.BWLimit, r.Context())}
	}
	http.ServeContent(w, r, name, info.ModTime(), rs)
}

// inlineContentType decides whether a file may be displayed in the browser or
// must be downloaded. Anything scriptable (HTML, SVG, XML, JS) is forced to
// download; text-like data is served as text/plain so it cannot be sniffed as
// HTML.
func inlineContentType(name string) (string, bool) {
	switch strings.ToLower(pathpkg.Ext(name)) {
	case ".png":
		return "image/png", true
	case ".jpg", ".jpeg":
		return "image/jpeg", true
	case ".gif":
		return "image/gif", true
	case ".webp":
		return "image/webp", true
	case ".avif":
		return "image/avif", true
	case ".bmp":
		return "image/bmp", true
	case ".ico":
		return "image/x-icon", true
	case ".pdf":
		return "application/pdf", true
	case ".mp4":
		return "video/mp4", true
	case ".webm":
		return "video/webm", true
	case ".mp3":
		return "audio/mpeg", true
	case ".wav":
		return "audio/wav", true
	case ".ogg":
		return "audio/ogg", true
	case ".txt", ".log", ".md", ".csv", ".tsv", ".json", ".yaml", ".yml",
		".ini", ".conf", ".cfg", ".bed", ".vcf", ".fasta", ".fa", ".fq", ".fastq":
		return "text/plain; charset=utf-8", true
	}
	return "", false
}

// contentDisposition builds a Content-Disposition header value. Non-ASCII
// names (a Chinese service name, a data file name) cannot travel in a plain
// quoted-string, so they are also emitted as an RFC 5987 filename* with an
// ASCII fallback for old clients.
func contentDisposition(kind, name string) string {
	safe := strings.NewReplacer(`"`, "", `\\`, "", "\r", "", "\n", "").Replace(name)
	if isASCII(safe) {
		return kind + `; filename="` + safe + `"`
	}
	fallback := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, safe)
	return kind + `; filename="` + fallback + `"; filename*=UTF-8''` + url.PathEscape(safe)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7e || s[i] < 0x20 {
			return false
		}
	}
	return true
}

// serveZip streams the directory tree as a zip archive, produced on the fly
// (no temp files, bounded memory) so it works for trees larger than a temp
// copy would allow; the trade-off is that the response has no Content-Length,
// hence no resumable download.
func serveZip(w http.ResponseWriter, r *http.Request, root *os.Root, fsPath, rel string, opts Options) {
	base := pathpkg.Base(rel)
	if rel == "/" {
		base = sanitizeFilename(opts.Name)
	}
	if base == "" || base == "." || base == "/" {
		base = "download"
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDisposition("attachment", base+".zip"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	zw := zip.NewWriter(w)
	defer zw.Close()

	// A zip body cannot be truncated with an HTTP error once writing has
	// started, so unreadable sub-entries are skipped instead of aborting.
	addToZip(zw, root, fsPath, "", opts, r.Context(), 0)
}

func addToZip(zw *zip.Writer, root *os.Root, fsPath, zipPath string, opts Options, ctx context.Context, depth int) {
	if depth > maxZipDepth {
		return
	}
	entries, err := readDir(root, fsPath)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !opts.ShowHidden && strings.HasPrefix(name, ".") {
			continue
		}
		childFS := pathpkg.Join(fsPath, name)
		childZip := pathpkg.Join(zipPath, name)
		info, err := root.Stat(childFS)
		if err != nil {
			continue
		}
		if info.IsDir() {
			// Store the directory entry itself so empty directories survive.
			hdr := &zip.FileHeader{Name: childZip + "/", Method: zip.Store, Modified: info.ModTime()}
			hdr.SetMode(info.Mode())
			if _, err := zw.CreateHeader(hdr); err != nil {
				return
			}
			addToZip(zw, root, childFS, childZip, opts, ctx, depth+1)
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		cf, err := root.Open(childFS)
		if err != nil {
			continue
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			cf.Close()
			continue
		}
		hdr.Name = childZip
		hdr.Method = zip.Deflate
		dst, err := zw.CreateHeader(hdr)
		if err == nil {
			var src io.Reader = cf
			if opts.BWLimit > 0 {
				src = rate.NewLimitedReaderContext(cf, opts.BWLimit, ctx)
			}
			io.Copy(dst, src)
		}
		cf.Close()
	}
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	name = strings.NewReplacer("/", "-", "\\", "-", ":", "-", "\r", "", "\n", "").Replace(name)
	if name == "" || name == "." || name == ".." {
		return "download"
	}
	return name
}

// limitedReadSeeker rate-limits reads while staying seekable, so
// http.ServeContent keeps Range/If-Modified-Since support under a bandwidth
// cap.
type limitedReadSeeker struct {
	rs  io.ReadSeeker
	lim io.Reader
}

func (l *limitedReadSeeker) Read(p []byte) (int, error) { return l.lim.Read(p) }

func (l *limitedReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return l.rs.Seek(offset, whence)
}

func writeFSError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, fs.ErrPermission):
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		http.Error(w, "unavailable", http.StatusInternalServerError)
	}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
