// Package httpapi exposes the PII redaction service over HTTP. The service is
// stateless: every request carries its full input in the body.
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"unicode/utf8"

	"task044-piimask/internal/pii"
)

// API is the HTTP façade for the pii package.
type API struct{}

// New creates an API.
func New() *API { return &API{} }

// Handler returns the HTTP handler for all routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /redact", a.redact)
	return mux
}

// writeJSON encodes v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON reads a size-limited JSON body into dst with strict field
// checking. It reports whether decoding succeeded.
func decodeJSON(r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dst) != nil
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// redactRequest is the body for POST /redact.
type redactRequest struct {
	Text     string `json:"text"`
	MaskChar string `json:"mask_char"`
}

func (a *API) redact(w http.ResponseWriter, r *http.Request) {
	var req redactRequest
	if !decodeJSON(r, &req) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体不是合法 JSON", "status": http.StatusBadRequest})
		return
	}
	if req.Text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "text 缺失", "status": http.StatusBadRequest})
		return
	}
	mc := req.MaskChar
	if mc == "" {
		mc = "*"
	}
	if utf8.RuneCountInString(mc) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "mask_char 必须为单个字符", "status": http.StatusBadRequest})
		return
	}
	res := pii.Redact(req.Text, mc)
	writeJSON(w, http.StatusOK, res)
}
