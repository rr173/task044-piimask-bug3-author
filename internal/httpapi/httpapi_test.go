package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedactEndpoint(t *testing.T) {
	srv := httptest.NewServer(New().Handler())
	defer srv.Close()

	body := map[string]any{"text": "contact alice@example.com or 13812345678"}
	buf, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/redact", "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var out struct {
		Text       string `json:"text"`
		Redactions []struct {
			Type   string `json:"type"`
			Start  int    `json:"start"`
			End    int    `json:"end"`
			Masked string `json:"masked"`
		} `json:"redactions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Text != "contact a****@example.com or 138****5678" {
		t.Errorf("text=%q", out.Text)
	}
	if len(out.Redactions) != 2 {
		t.Fatalf("redactions=%v", out.Redactions)
	}
	if out.Redactions[0].Type != "email" || out.Redactions[0].Masked != "a****@example.com" {
		t.Errorf("email=%v", out.Redactions[0])
	}
	if out.Redactions[1].Type != "phone" || out.Redactions[1].Masked != "138****5678" {
		t.Errorf("phone=%v", out.Redactions[1])
	}
}

func TestRedactErrors(t *testing.T) {
	srv := httptest.NewServer(New().Handler())
	defer srv.Close()

	cases := []struct {
		name    string
		payload string
		want    int
	}{
		{"bad json", "{not json", http.StatusBadRequest},
		{"unknown field", `{"text":"x","extra":1}`, http.StatusBadRequest},
		{"missing text", `{"mask_char":"*"}`, http.StatusBadRequest},
		{"empty text", `{"text":""}`, http.StatusBadRequest},
		{"multi-char mask", `{"text":"x","mask_char":"ab"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		resp, err := http.Post(srv.URL+"/redact", "application/json", bytes.NewReader([]byte(c.payload)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: status=%d want %d", c.name, resp.StatusCode, c.want)
		}
	}
}

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(New().Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "ok" {
		t.Errorf("status=%q", out["status"])
	}
}
