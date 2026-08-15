package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/seqyuan/goprox/internal/auth"
	"github.com/seqyuan/goprox/internal/config"
)

// Handler handles REST API requests for service management.
type Handler struct {
	Registry      *config.UserRegistry
	SessionSecret string
}

// NewHandler creates a new API handler.
func NewHandler(registry *config.UserRegistry, sessionSecret string) *Handler {
	return &Handler{
		Registry:      registry,
		SessionSecret: sessionSecret,
	}
}

// ServeHTTP implements http.Handler. Returns false if the request is not an API route.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path

	// Only handle known API routes
	isAPI := path == "/api/services" ||
		path == "/api/services/layout" ||
		strings.HasPrefix(path, "/api/services/")

	if !isAPI {
		return false
	}

	// CSRF guard: state-changing requests from browsers must carry an Origin
	// matching the gateway's own host. Browsers always send Origin on
	// POST/PUT/DELETE, so cross-site (and cross-host) pages are rejected.
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !auth.SameOriginRequest(r) {
		writeJSON(w, 403, map[string]string{"error": "cross-origin request rejected"})
		return true
	}

	username := h.requireSession(w, r)
	if username == "" {
		return true
	}

	switch {
	case path == "/api/services" && r.Method == "GET":
		h.handleListServices(w, r, username)
	case path == "/api/services" && r.Method == "POST":
		h.handleAddService(w, r, username)
	case path == "/api/services/layout" && r.Method == "PUT":
		h.handleUpdateLayout(w, r, username)
	case strings.HasPrefix(path, "/api/services/") && r.Method == "DELETE":
		id := strings.TrimPrefix(path, "/api/services/")
		h.handleDeleteService(w, username, id)
	case strings.HasPrefix(path, "/api/services/") && r.Method == "PUT":
		id := strings.TrimPrefix(path, "/api/services/")
		h.handleUpdateService(w, r, username, id)
	default:
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}

	return true
}

func (h *Handler) requireSession(w http.ResponseWriter, r *http.Request) string {
	session := h.sessionFromCookies(r.Header.Get("Cookie"))
	if !session.Valid || session.UserID == "" {
		writeJSON(w, 401, map[string]string{"error": "Unauthorized"})
		return ""
	}
	return session.UserID
}

// currentSessionRev returns the per-account session revision derived from the
// user's current password hash.
func (h *Handler) currentSessionRev(username string) string {
	if !config.IsValidUsername(username) {
		return ""
	}
	uc := h.Registry.GetUserConfigForLogin(username)
	if uc == nil {
		return ""
	}
	return auth.SessionRev(uc.Auth.PasswordHash)
}

// sessionFromCookies validates the session cookie, binding it to the user's
// current password-hash revision so password changes revoke old sessions.
func (h *Handler) sessionFromCookies(cookieHeader string) auth.SessionResult {
	cookies := auth.ParseCookies(cookieHeader)
	token := cookies[auth.SessionCookieName]
	if token == "" {
		return auth.SessionResult{}
	}
	userID, _, _, err := auth.SessionTokenParts(token)
	if err != nil || userID == "" {
		return auth.SessionResult{}
	}
	return auth.ValidateSessionToken(token, h.SessionSecret, h.currentSessionRev(userID))
}

func (h *Handler) getConfigPath(username string) (string, error) {
	user := h.Registry.GetUser(username)
	if user == nil {
		return "", fmt.Errorf("user config not found")
	}
	return user.ConfigPath, nil
}

func (h *Handler) handleListServices(w http.ResponseWriter, r *http.Request, username string) {
	user := h.Registry.GetUser(username)
	if user == nil {
		writeJSON(w, 200, map[string]interface{}{"services": []interface{}{}, "writable": false})
		return
	}

	writable := isWritable(user.ConfigPath)
	writeJSON(w, 200, map[string]interface{}{
		"services": user.Config.Services,
		"writable": writable,
	})
}

func (h *Handler) handleAddService(w http.ResponseWriter, r *http.Request, username string) {
	var body addServiceBody
	if err := parseBody(r, &body); err != nil {
		writeBodyError(w, err)
		return
	}

	// Reject empty names and oversized fields so a stray request cannot
	// create a nonsense "service" card or bloat the dashboard page.
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeJSON(w, 400, map[string]string{"error": "name is required"})
		return
	}
	if len(name) > 200 || len(body.Description) > 500 || len(body.Category) > 100 {
		writeJSON(w, 400, map[string]string{"error": "field too long (name ≤ 200, description ≤ 500, category ≤ 100 chars)"})
		return
	}

	configPath, err := h.getConfigPath(username)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if !isWritable(configPath) {
		writeJSON(w, 403, map[string]string{"error": "config is not writable"})
		return
	}

	// WebSocket defaults to true unless explicitly disabled.
	ws := true
	if body.WebSocket != nil {
		ws = *body.WebSocket
	}

	svc := config.ServiceConfig{
		ID:          config.SlugifyName(name),
		Name:        name,
		Description: body.Description,
		Host:        body.Host,
		Port:        body.Port,
		BackendPath: body.BackendPath,
		WebSocket:   ws,
		Category:    body.Category,
	}
	if body.Path != "" {
		svc.Path = config.NormalizePath(body.Path)
	}
	// An empty Path means config.AddService auto-generates a unique one from
	// the (also unique-ified) ID.

	added, err := config.AddService(configPath, svc)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	h.Registry.Reload()
	writeJSON(w, 201, map[string]interface{}{"service": added})
}

func (h *Handler) handleUpdateLayout(w http.ResponseWriter, r *http.Request, username string) {
	var body layoutBody
	if err := parseBody(r, &body); err != nil {
		writeBodyError(w, err)
		return
	}

	configPath, err := h.getConfigPath(username)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if !isWritable(configPath) {
		writeJSON(w, 403, map[string]string{"error": "config is not writable"})
		return
	}

	items := make([]config.LayoutItem, len(body.Items))
	for i, item := range body.Items {
		items[i] = config.LayoutItem{
			ID:       item.ID,
			Order:    item.Order,
			Category: item.Category,
		}
	}

	if err := config.UpdateServicesLayout(configPath, items); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	h.Registry.Reload()
	user := h.Registry.GetUser(username)
	services := []config.ServiceConfig{}
	if user != nil {
		services = user.Config.Services
	}
	writeJSON(w, 200, map[string]interface{}{"services": services})
}

func (h *Handler) handleDeleteService(w http.ResponseWriter, username, id string) {
	configPath, err := h.getConfigPath(username)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if !isWritable(configPath) {
		writeJSON(w, 403, map[string]string{"error": "config is not writable"})
		return
	}

	if err := config.RemoveService(configPath, id); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	h.Registry.Reload()
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (h *Handler) handleUpdateService(w http.ResponseWriter, r *http.Request, username, id string) {
	var body updateBody
	if err := parseBody(r, &body); err != nil {
		writeBodyError(w, err)
		return
	}

	// A provided name must be non-empty and bounded (mirrors handleAddService).
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if name == "" {
			writeJSON(w, 400, map[string]string{"error": "name cannot be empty"})
			return
		}
		if len(name) > 200 {
			writeJSON(w, 400, map[string]string{"error": "name too long (≤ 200 chars)"})
			return
		}
	}
	// Description/category bounds apply even when name is not being changed.
	if (body.Description != nil && len(*body.Description) > 500) || (body.Category != nil && len(*body.Category) > 100) {
		writeJSON(w, 400, map[string]string{"error": "field too long (description ≤ 500, category ≤ 100 chars)"})
		return
	}

	configPath, err := h.getConfigPath(username)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	if !isWritable(configPath) {
		writeJSON(w, 403, map[string]string{"error": "config is not writable"})
		return
	}

	update := config.ServiceUpdate{
		Name:        body.Name,
		Description: body.Description,
		Host:        body.Host,
		Port:        body.Port,
		Path:        body.Path,
		BackendPath: body.BackendPath,
		WebSocket:   body.WebSocket,
		Category:    body.Category,
	}

	if err := config.UpdateService(configPath, id, update); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	h.Registry.Reload()
	user := h.Registry.GetUser(username)
	var updated *config.ServiceConfig
	if user != nil {
		for _, s := range user.Config.Services {
			if s.ID == id {
				updated = &s
				break
			}
		}
	}
	writeJSON(w, 200, map[string]interface{}{"service": updated})
}

// Request body types

type addServiceBody struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port"`
	Path        string `json:"path,omitempty"`
	BackendPath string `json:"backend_path,omitempty"`
	WebSocket   *bool  `json:"websocket,omitempty"`
	Category    string `json:"category,omitempty"`
}

type layoutBody struct {
	Items []layoutItemBody `json:"items"`
}

type layoutItemBody struct {
	ID       string `json:"id"`
	Order    int    `json:"order"`
	Category string `json:"category,omitempty"`
}

type updateBody struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Host        *string `json:"host,omitempty"`
	Port        *int    `json:"port,omitempty"`
	Path        *string `json:"path,omitempty"`
	BackendPath *string `json:"backend_path,omitempty"`
	WebSocket   *bool   `json:"websocket,omitempty"`
	Category    *string `json:"category,omitempty"`
}

// Helpers

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// maxBodySize caps JSON request bodies. Bodies larger than this are rejected
// with 413 instead of being silently truncated mid-JSON.
const maxBodySize = 1 << 16 // 64KB

var errBodyTooLarge = fmt.Errorf("request body too large (max 64KB)")

func parseBody(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("missing body")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(data) > maxBodySize {
		return errBodyTooLarge
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// writeBodyError maps a parseBody error to the right HTTP status: 413 for
// oversized bodies, 400 otherwise.
func writeBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		writeJSON(w, 413, map[string]string{"error": "request body too large"})
		return
	}
	writeJSON(w, 400, map[string]string{"error": err.Error()})
}

func isWritable(path string) bool {
	return config.IsWritable(path)
}
