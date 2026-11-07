package server

// 代理路由：/proxy 前缀、Referer、route Cookie、default_service、root_absolute
// 与内置文件服务。

import (
	"io"
	"log"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
	"time"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
	"github.com/seqyuan/goprox/internal/files"
	"github.com/seqyuan/goprox/internal/proxy"
	"github.com/seqyuan/goprox/internal/web"
)

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		// Send the unauthenticated user to the login page and remember where
		// they were headed so they land back on their service after login.
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}

	// Refresh session if needed
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := s.issueSessionCookie(session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	path := r.URL.Path

	// Try multi-user path: /proxy/{user}/{service}/...
	multiMatch := s.registry.FindService(path)
	if multiMatch != nil {
		pathUser := config.UsernameFromProxyPath(path)
		if pathUser == "" || pathUser != session.UserID {
			// Match vhost behavior: hide other users' services instead of
			// returning 403, which would confirm that the path exists.
			sendHTML(w, http.StatusNotFound, web.NotFoundPage(s.siteTitle))
			return
		}
		s.proxyRequest(w, r, multiMatch)
		return
	}

	// Try legacy path
	legacyMatch := s.registry.FindLegacyService(path, session.UserID)
	if legacyMatch == nil {
		sendHTML(w, 404, web.NotFoundPage(s.siteTitle))
		return
	}

	s.proxyRequest(w, r, legacyMatch)
}

// proxyRequest forwards a direct /proxy/{user}/{service}/... request, rewriting the path.

func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, match *config.ServiceMatch) {
	// Check WebSocket upgrade requests
	if isWebSocketUpgrade(r) && !match.Service.WebSocket {
		http.Error(w, "WebSocket not enabled for this service", http.StatusForbidden)
		return
	}

	forwardCtx := proxy.BuildProxyForwardContext(r, match.Username, match.Service.Path, match.Legacy)
	forwardCtx.SSO = s.state.SSO
	// The injected <base> must point at the directory of the actual document
	// (e.g. /proxy/user/svc/report/page.html -> /proxy/user/svc/report/), not
	// the service prefix, so relative links in plain HTML files in
	// subdirectories resolve correctly.
	forwardCtx.Base = proxy.BaseForPath(forwardCtx.Prefix, match.RemainingPath)
	s.setRouteCookies(w, r, forwardCtx.Prefix)
	r.URL.Path = match.RemainingPath
	s.forwardToBackend(w, r, match.Service, forwardCtx)
}

// forwardAsIs forwards a request to the backend keeping the current request path intact.
// Used for referer-based, route-cookie-based, and backend-login routing.

func (s *Server) forwardAsIs(w http.ResponseWriter, r *http.Request, match *config.ServiceMatch) {
	// Check WebSocket upgrade requests
	if isWebSocketUpgrade(r) && !match.Service.WebSocket {
		http.Error(w, "WebSocket not enabled for this service", http.StatusForbidden)
		return
	}

	forwardCtx := proxy.BuildProxyForwardContext(r, match.Username, match.Service.Path, match.Legacy)
	forwardCtx.SSO = s.state.SSO
	forwardCtx.Mode = proxy.ForwardAsIs
	// As-is forwarding (default_service, Referer, route cookie) keeps the
	// browser path unchanged, so relative links must resolve against that
	// path, not the canonical /proxy/... prefix. Otherwise a page such as
	// /vault/project-db that uses ../_app/... would request
	// /proxy/<user>/_app/... and miss the service. Canonical /proxy/...
	// requests never reach forwardAsIs; proxyRequest computes their base
	// from the service prefix.
	if !strings.HasPrefix(r.URL.Path, "/proxy/") {
		forwardCtx.Base = proxy.BaseForPath("", r.URL.Path)
	}
	s.setRouteCookies(w, r, forwardCtx.Prefix)
	s.forwardToBackend(w, r, match.Service, forwardCtx)
}

func (s *Server) forwardToBackend(w http.ResponseWriter, r *http.Request, svc *config.ServiceConfig, fc proxy.ProxyForwardContext) {
	start := time.Now()

	// A kind:"files" service has no backend: the gateway serves the configured
	// directory itself (read-only listing, file download, zip export).
	if svc.Kind == config.ServiceKindFiles {
		rec := &statusRecorder{ResponseWriter: w}
		s.serveFilesService(rec, r, svc, fc)
		s.recordAccess(fc.Username, svc, r, fc.OriginalPath, rec.statusCode(), time.Since(start), "")
		return
	}
	// Go's http.Server.ReadTimeout caps the whole request body, which would
	// abort any upload taking longer than 60s. For proxied requests reset the
	// deadline to an idle timeout before every body read: a continuously
	// uploading client is not cut off, while a stalled upload still fails.
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &idleReadBody{
			ReadCloser: r.Body,
			rc:         http.NewResponseController(w),
			timeout:    proxyBodyIdleTimeout,
		}
	}

	rp := proxy.NewReverseProxy(svc, fc)
	rp.Transport = s.transport
	// Go's ReverseProxy logs body-copy errors ("unexpected EOF") through its
	// internal logger whenever the client disconnects mid-stream (SSE tab
	// close, navigation). Those are expected, not outages, and meaningful
	// failures are already logged by ErrorHandler below, so silence the
	// standard-library noise.
	rp.ErrorLog = log.New(io.Discard, "", 0)
	// Add error handler: log the full error server-side, reply generically so
	// backend host/port details are not leaked to clients.
	failure := ""
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// The client went away (tab closed / navigation during a stream); the
		// connection is dead, so there is nothing to write and the "context
		// canceled" error is expected, not an outage.
		if r.Context().Err() != nil {
			return
		}
		failure = err.Error()
		log.Printf("[goprox] proxy error: service=%s, path=%s, error=%v", svc.ID, r.URL.Path, err)
		switch {
		case strings.Contains(err.Error(), "connection refused"):
			http.Error(w, "Service unavailable: backend not responding", http.StatusBadGateway)
		case strings.Contains(err.Error(), "timeout"):
			http.Error(w, "Service timeout: backend took too long to respond", http.StatusGatewayTimeout)
		default:
			http.Error(w, "Proxy error", http.StatusBadGateway)
		}
	}
	rp.ServeHTTP(w, r)
	s.recordAccess(fc.Username, svc, r, fc.OriginalPath, 0, time.Since(start), failure)
}

// serveFilesService answers a request for a kind:"files" service from the
// local filesystem. The service owner (the session user) is already enforced by
// the routing that got here; the path itself is confined to Root by the files
// package (os.Root: no "..", no root-escaping symlinks).

func (s *Server) serveFilesService(w http.ResponseWriter, r *http.Request, svc *config.ServiceConfig, fc proxy.ProxyForwardContext) {
	// The browser-visible prefix the listing's links must be built from: the
	// canonical /proxy/<user>/<svc> in prefix mode, the host root otherwise
	// (vhost and bare-path as-is routing both live at the gateway root).
	base := ""
	rel := r.URL.Path
	if fc.Mode == proxy.ForwardPrefix {
		base = fc.Prefix
	} else if svc.Path != "" && svc.Path != "/" {
		// A bare request that arrived with the service path attached (typed
		// URL, or a root-absolute link from a proxied page) still maps onto the
		// directory root rather than into a subdirectory named like the path.
		if r.URL.Path == svc.Path || strings.HasPrefix(r.URL.Path, svc.Path+"/") {
			rel = strings.TrimPrefix(r.URL.Path, svc.Path)
		}
	}
	files.Serve(w, r, files.Options{
		Root:       svc.Root,
		RelPath:    rel,
		LinkBase:   base,
		ShowHidden: svc.ShowHidden,
		Name:       svc.Name,
		BWLimit:    svc.BWLimit,
	})
}

func (s *Server) handleRefererProxy(w http.ResponseWriter, r *http.Request) bool {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		return false
	}

	// Refresh session if needed
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := s.issueSessionCookie(session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	referer := r.Header.Get("Referer")
	if referer == "" {
		return false
	}

	// Extract the path only when the Referer belongs to this gateway authority.
	refPath := s.refererPath(r)
	if refPath == "" {
		return false
	}

	match := s.registry.FindService(refPath)
	if match == nil {
		match = s.registry.FindLegacyService(refPath, session.UserID)
	}
	if match == nil {
		return false
	}

	// Verify user matches
	pathUser := config.UsernameFromProxyPath(refPath)
	if pathUser != "" && pathUser != session.UserID {
		return false
	}

	s.forwardAsIs(w, r, match)
	return true
}

func (s *Server) handleRouteCookieProxy(w http.ResponseWriter, r *http.Request) bool {
	route := s.cookieNames.RouteForRequest(r.Header.Get("Cookie"), r.URL.Path, r.Header.Get("Referer"))
	if route == "" {
		return false
	}

	// Route cookies are context hints, not credentials: without a valid
	// session they must never grant backend access (the session may have
	// expired or the user may have logged out).
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return true
	}

	// Refresh session if needed
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		cookie := s.issueSessionCookie(session.UserID, secure)
		w.Header().Add("Set-Cookie", cookie)
	}

	match := s.registry.FindService(route)
	if match == nil {
		match = s.registry.FindLegacyService(route, session.UserID)
	}
	if match == nil {
		return false
	}

	pathUser := config.UsernameFromProxyPath(route)
	if pathUser != "" && pathUser != session.UserID {
		return false
	}

	s.forwardAsIs(w, r, match)
	return true
}

// handleDefaultServiceProxy forwards unclaimed bare gateway paths to the
// user's configured default service (DefaultService), so root-routed SPAs
// (Nuxt / Next / Vite client routers, which match window.location.pathname
// against root routes and cannot understand a /proxy/<user>/ prefix) work at
// the gateway root with zero app-side basePath/baseURL changes. It runs only
// after route-cookie and Referer forwarding have failed; forwardAsIs stamps
// the route cookies that keep subsequent sub-resource requests on the same
// service. Without a valid session the request falls through to the 404.

func (s *Server) handleDefaultServiceProxy(w http.ResponseWriter, r *http.Request) bool {
	return s.forwardToDefaultService(w, r)
}

// handleDefaultServicePage deterministically routes page-like bare paths
// (SPA views like /dashboard, not assets or API calls) to the user's default
// service, before Referer / route-cookie forwarding. This makes root-based
// SPA navigation stable regardless of which other services were visited most
// recently; resource-like paths are left to the Referer/route-cookie chain so
// they stick to the page that issued them.

func (s *Server) handleDefaultServicePage(w http.ResponseWriter, r *http.Request) bool {
	if !barePathIsPage(r.URL.Path) {
		return false
	}
	return s.forwardToDefaultService(w, r)
}

func (s *Server) forwardToDefaultService(w http.ResponseWriter, r *http.Request) bool {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		return false
	}
	user := s.registry.GetUser(session.UserID)
	if user == nil || user.Config.DefaultService == "" {
		return false
	}
	svc := config.ServiceByID(user.Config.Services, user.Config.DefaultService)
	if svc == nil {
		return false
	}
	// Keep default-service page navigations on the same sliding-session policy
	// as dashboard/proxy/API requests; otherwise a root-routed SPA that only
	// makes page-like requests can expire while actively in use.
	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		w.Header().Add("Set-Cookie", s.issueSessionCookie(session.UserID, auth.IsSecureRequest(r)))
	}
	match := &config.ServiceMatch{
		Username:      session.UserID,
		Service:       svc,
		RemainingPath: r.URL.Path,
	}
	s.forwardAsIs(w, r, match)
	return true
}

// barePathIsPage reports whether an unclaimed bare gateway path looks like a
// page navigation (a client-routed SPA view) rather than a static asset or
// API call. Page-like paths are routed to the user's default service
// deterministically; resource-like paths (segments with file extensions, or
// paths under known asset/API roots) fall back to Referer / route-cookie
// forwarding so they follow the page that requested them.

func barePathIsPage(p string) bool {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	lower := strings.ToLower(p)
	for _, seg := range strings.Split(lower, "/") {
		if i := strings.LastIndexByte(seg, '.'); i > 0 && i < len(seg)-1 {
			return false
		}
	}
	for _, root := range []string{
		"/api/", "/plugins/", "/_nuxt/", "/_next/", "/assets/", "/static/",
		"/vendors/", "/files/", "/favicon.", "/manifest.webmanifest",
	} {
		if strings.HasPrefix(lower, root) {
			return false
		}
	}
	return true
}

// bestBareService returns the user's service whose frontend path is the
// longest prefix of path, or nil when path does not belong to a service path.

func (s *Server) bestBareService(username, path string) *config.ServiceConfig {
	user := s.registry.GetUser(username)
	if user == nil {
		return nil
	}

	var bestSvc *config.ServiceConfig
	bestLen := -1
	for i := range user.Config.Services {
		svc := &user.Config.Services[i]
		if path == svc.Path || strings.HasPrefix(path, svc.Path+"/") {
			if len(svc.Path) > bestLen {
				bestLen = len(svc.Path)
				bestSvc = svc
			}
		}
	}
	return bestSvc
}

// forwardBareService proxies a non-GET bare request directly to the service
// that owns the path. A redirect (used for GET) would lose the method/body, so
// strip the service prefix and forward instead.

func (s *Server) forwardBareService(w http.ResponseWriter, r *http.Request, username string) bool {
	svc := s.bestBareService(username, r.URL.Path)
	if svc == nil {
		return false
	}
	remaining := r.URL.Path[len(svc.Path):]
	if remaining == "" {
		remaining = "/"
	}
	s.proxyRequest(w, r, &config.ServiceMatch{
		Username:      username,
		Service:       svc,
		RemainingPath: remaining,
	})
	return true
}

func (s *Server) redirectBareService(w http.ResponseWriter, r *http.Request, username string) bool {
	bestSvc := s.bestBareService(username, r.URL.Path)
	if bestSvc == nil {
		return false
	}

	rest := r.URL.Path[len(bestSvc.Path):]
	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, "/proxy/"+username+bestSvc.Path+rest+query, http.StatusFound)
	return true
}

// isPassiveSubresource reports whether this is an image/favicon load. Such
// requests are issued by the dashboard for every card and must not update the
// global "most recently visited service" marker: otherwise the root-absolute /
// default-service fallback would point at whichever favicon loaded last.

func isPassiveSubresource(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Dest"), "image") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(pathpkg.Base(r.URL.Path)), "favicon.")
}

// setRouteCookies writes the per-service route cookie on every proxied
// response, and the global recent-service cookie only for real page/API
// traffic (not passive image/favicon subresources).

func (s *Server) setRouteCookies(w http.ResponseWriter, r *http.Request, prefix string) {
	cookies := s.cookieNames.SetRouteCookies(prefix)
	if isPassiveSubresource(r) {
		// SetRouteCookies returns [per-service, global]; keep only the former.
		cookies = cookies[:1]
	}
	for _, c := range cookies {
		w.Header().Add("Set-Cookie", c)
	}
}

// handleRootAbsoluteService routes a bare request back to a service that opted
// into root_absolute. Such apps emit root-absolute URLs (/docs/, /static/...)
// while being hosted under /proxy/<user>/<service>/; the current page
// (Referer) is the most precise owner, with the route cookie as a fallback for
// reloads/bookmarks after a previous visit.
//
// It runs before default_service page routing so an explicit opt-in can
// override default_service. Requests that match a service path are left alone;
// redirectBareService/default routing keeps their existing semantics.

func (s *Server) handleRootAbsoluteService(w http.ResponseWriter, r *http.Request, session auth.SessionResult) bool {
	if s.bestBareService(session.UserID, r.URL.Path) != nil {
		return false
	}

	match, canonicalReferer := s.matchRootAbsoluteReferer(r, session.UserID)
	if match == nil && !canonicalReferer {
		// No canonical /proxy/... page identified by Referer: a reload or
		// bookmark can still use the most recent route cookie.
		route := s.cookieNames.RouteForRequest(r.Header.Get("Cookie"), r.URL.Path, r.Header.Get("Referer"))
		if route != "" {
			match = s.matchRouteForUser(route, session.UserID)
		}
	}
	if match == nil || !match.Service.RootAbsolute {
		return false
	}

	if auth.ShouldRefreshSession(session, s.state.Auth.SessionTTL) {
		secure := auth.IsSecureRequest(r)
		w.Header().Add("Set-Cookie", s.issueSessionCookie(session.UserID, secure))
	}
	s.forwardAsIs(w, r, match)
	return true
}

// matchRootAbsoluteReferer resolves the current page's service from the
// Referer. The bool reports whether the Referer is a canonical /proxy/...
// path (whether or not it points at a root_absolute service): a canonical
// referer is authoritative, so a stale route cookie must not override it.

func (s *Server) matchRootAbsoluteReferer(r *http.Request, username string) (*config.ServiceMatch, bool) {
	refPath := s.refererPath(r)
	if refPath == "" {
		return nil, false
	}
	if !strings.HasPrefix(refPath, "/proxy/") {
		// Bare/external referer: no canonical page identity, so the caller
		// may fall back to the route cookie.
		return nil, false
	}
	match := s.registry.FindServiceForUser(refPath, username)
	if match == nil {
		// Canonical proxy path with no matching service (deleted/unknown):
		// authoritative, but not ours.
		return nil, true
	}
	if match.Username != username {
		// Another user's canonical page: authoritative, but not ours.
		return nil, true
	}
	if match.Service.RootAbsolute {
		return match, true
	}
	// Canonical page of a non-flagged service: do not let a stale route
	// cookie for a different service steal its bare paths.
	return nil, true
}

// wantsHTML reports whether the request looks like a browser document
// navigation (Accept: text/html), as opposed to an XHR/fetch/API call.

func (s *Server) handleProxyEscape(w http.ResponseWriter, r *http.Request) bool {
	// When a user lands on /?xxx (e.g. /?refresh=1) after escaping the proxy
	// prefix, redirect them back to the correct proxy URL via the route cookie.
	if r.URL.RawQuery == "" {
		return false
	}
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		return false
	}
	route := s.cookieNames.RouteForRequest(
		r.Header.Get("Cookie"), "", s.refererPath(r),
	)
	if route == "" || !strings.HasPrefix(route, "/proxy/"+session.UserID+"/") {
		return false
	}
	target := route
	if !strings.HasSuffix(target, "/") {
		target += "/"
	}
	target += "?" + r.URL.RawQuery
	http.Redirect(w, r, target, http.StatusFound)
	return true
}

func (s *Server) findBackendService(r *http.Request, username string) *config.ServiceMatch {
	// Referer is the strongest signal for backend-originated login posts, but
	// only when it comes from this same gateway authority: an external page
	// controls its own path and must not choose a backend.
	refPath := s.refererPath(r)
	if refPath != "" {
		if match := s.matchRouteForUser(refPath, username); match != nil {
			return match
		}
	}

	route := s.cookieNames.RouteForRequest(r.Header.Get("Cookie"), r.URL.Path, refPath)
	if route == "" {
		return nil
	}
	return s.matchRouteForUser(route, username)
}

func (s *Server) matchRouteForUser(route, username string) *config.ServiceMatch {
	match := s.registry.FindService(route)
	if match == nil {
		match = s.registry.FindLegacyService(route, username)
	}
	if match == nil {
		return nil
	}
	pathUser := config.UsernameFromProxyPath(route)
	if pathUser != "" && pathUser != username {
		return nil
	}
	return match
}

func (s *Server) handleBackendLogin(w http.ResponseWriter, r *http.Request) bool {
	session := s.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		return false
	}

	// Try to find target service from referer or route cookie
	match := s.findBackendService(r, session.UserID)
	if match == nil {
		return false
	}

	// Improved detection: check if this is a GoProx login vs backend login
	ct := r.Header.Get("Content-Type")
	referer := r.Header.Get("Referer")

	// GoProx login characteristics:
	// 1. Path is exactly /login (not /proxy/.../login)
	// 2. Referer is not inside a proxied service
	// 3. Content-Type is form data
	// (Origin is already enforced by the caller's SameOriginRequest guard;
	// a browser Origin never contains a path, so testing it here was a no-op.)
	isGoProxLogin := r.URL.Path == "/login" &&
		strings.Contains(ct, "application/x-www-form-urlencoded") &&
		!strings.Contains(referer, "/proxy/")

	if isGoProxLogin {
		// Let GoProx handle this login
		return false
	}

	// This appears to be a backend service login form, forward it
	s.forwardAsIs(w, r, match)
	return true
}

// findBackendService tries to locate the target service from Referer or route cookie.
