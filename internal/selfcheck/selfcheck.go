// Package selfcheck runs an end-to-end verification of the PII redaction
// service against an in-process HTTP server. It is invoked by the --smoke-test
// flag and exits the process on completion.
//
// The service is stateless (every request carries its full input), so a single
// shared httptest server is used across all scenarios.
package selfcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"task044-piimask/internal/httpapi"
)

// client wraps the shared httptest server.
type client struct {
	base string
	c    *http.Client
	srv  *httptest.Server
}

func newClient() *client {
	srv := httptest.NewServer(httpapi.New().Handler())
	return &client{base: srv.URL, c: srv.Client(), srv: srv}
}

func (cl *client) close() { cl.srv.Close() }

func (cl *client) post(path string, body any) (int, map[string]any) {
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, cl.base+path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.c.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	return readBody(resp)
}

func (cl *client) postRaw(path string, raw []byte) (int, map[string]any) {
	req, _ := http.NewRequest(http.MethodPost, cl.base+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.c.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	return readBody(resp)
}

func (cl *client) get(path string) (int, map[string]any) {
	resp, err := cl.c.Get(cl.base + path)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	return readBody(resp)
}

func readBody(resp *http.Response) (int, map[string]any) {
	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &out)
	}
	return resp.StatusCode, out
}

// eqInt compares a JSON-decoded number to an expected int.
func eqInt(v any, want int) bool {
	f, ok := v.(float64)
	return ok && int(f) == want
}

// eqStr compares a JSON-decoded value to an expected string.
func eqStr(v any, want string) bool {
	s, ok := v.(string)
	return ok && s == want
}

// redactionsOf extracts the "redactions" array as a slice of maps.
func redactionsOf(body map[string]any) []map[string]any {
	arr, _ := body["redactions"].([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, x := range arr {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// findRedaction returns the first redaction of the given type, or nil.
func findRedaction(rs []map[string]any, typ string) map[string]any {
	for _, r := range rs {
		if eqStr(r["type"], typ) {
			return r
		}
	}
	return nil
}

// Run exercises the full HTTP API across the specification, returning nil if
// every behavior matches.
func Run() error {
	cl := newClient()
	defer cl.close()

	scenarios := []struct {
		name string
		fn   func(c *client) error
	}{
		{"健康检查", scenarioHealth},
		{"邮箱与手机号基本脱敏", scenarioEmailPhone},
		{"字节偏移正确", scenarioByteOffsets},
		{"身份证号有效脱敏", scenarioIDCardValid},
		{"身份证号校验位失败不脱敏", scenarioIDCardBroken},
		{"银行卡号有效脱敏", scenarioBankCardValid},
		{"银行卡号Luhn失败不脱敏", scenarioBankCardBroken},
		{"重叠邮箱优先于手机号", scenarioOverlapEmailPhone},
		{"身份证与银行卡同区间身份证优先", scenarioOverlapIDCardBankCard},
		{"掩码字符可配置", scenarioCustomMaskChar},
		{"无敏感信息原样返回", scenarioNoPII},
		{"多处邮箱各自脱敏", scenarioMultipleEmails},
		{"手机号位于数字串中不误判", scenarioPhoneInsideDigitRun},
		{"中文文本字节偏移", scenarioChineseByteOffsets},
		{"text缺失400", scenarioMissingText},
		{"mask_char非单字符400", scenarioBadMaskChar},
		{"非法JSON400", scenarioBadJSON},
		{"未知字段400", scenarioUnknownField},
	}
	for _, sc := range scenarios {
		if err := sc.fn(cl); err != nil {
			return fmt.Errorf("%s: %w", sc.name, err)
		}
	}
	return nil
}

func scenarioHealth(c *client) error {
	code, body := c.get("/healthz")
	if code != http.StatusOK || !eqStr(body["status"], "ok") {
		return fmt.Errorf("healthz: code=%d body=%v", code, body)
	}
	return nil
}

func scenarioEmailPhone(c *client) error {
	code, body := c.post("/redact", map[string]any{"text": "contact alice@example.com or 13812345678"})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	if !eqStr(body["text"], "contact a****@example.com or 138****5678") {
		return fmt.Errorf("text=%v", body["text"])
	}
	rs := redactionsOf(body)
	if len(rs) != 2 {
		return fmt.Errorf("redactions len=%d", len(rs))
	}
	em := findRedaction(rs, "email")
	if em == nil || !eqStr(em["masked"], "a****@example.com") {
		return fmt.Errorf("email=%v", em)
	}
	ph := findRedaction(rs, "phone")
	if ph == nil || !eqStr(ph["masked"], "138****5678") {
		return fmt.Errorf("phone=%v", ph)
	}
	return nil
}

func scenarioByteOffsets(c *client) error {
	// "contact " = 8 bytes; email len 17 -> [8,25); " or " = 4 -> phone [29,40)
	code, body := c.post("/redact", map[string]any{"text": "contact alice@example.com or 13812345678"})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d", code)
	}
	rs := redactionsOf(body)
	em := findRedaction(rs, "email")
	if em == nil || !eqInt(em["start"], 8) || !eqInt(em["end"], 25) {
		return fmt.Errorf("email offsets=%v want [8,25)", em)
	}
	ph := findRedaction(rs, "phone")
	if ph == nil || !eqInt(ph["start"], 29) || !eqInt(ph["end"], 40) {
		return fmt.Errorf("phone offsets=%v want [29,40)", ph)
	}
	return nil
}

func scenarioIDCardValid(c *client) error {
	code, body := c.post("/redact", map[string]any{"text": "id=11010519491231002X;"})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	if !eqStr(body["text"], "id=110105********002X;") {
		return fmt.Errorf("text=%v", body["text"])
	}
	rs := redactionsOf(body)
	if len(rs) != 1 || !eqStr(rs[0]["type"], "idcard") {
		return fmt.Errorf("redactions=%v", rs)
	}
	// span [3,21): "id=" is 3 bytes, idcard is 18 bytes
	if !eqInt(rs[0]["start"], 3) || !eqInt(rs[0]["end"], 21) {
		return fmt.Errorf("idcard offsets=%v want [3,21)", rs[0])
	}
	return nil
}

func scenarioIDCardBroken(c *client) error {
	// Wrong check digit (should be X); also Luhn-invalid -> nothing masked.
	text := "id=110105194912310021;"
	code, body := c.post("/redact", map[string]any{"text": text})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	if !eqStr(body["text"], text) {
		return fmt.Errorf("text changed: %v", body["text"])
	}
	if len(redactionsOf(body)) != 0 {
		return fmt.Errorf("redactions=%v want empty", redactionsOf(body))
	}
	return nil
}

func scenarioBankCardValid(c *client) error {
	code, body := c.post("/redact", map[string]any{"text": "card 4111111111111111 end"})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	if !eqStr(body["text"], "card 4111********1111 end") {
		return fmt.Errorf("text=%v", body["text"])
	}
	rs := redactionsOf(body)
	if len(rs) != 1 || !eqStr(rs[0]["type"], "bankcard") {
		return fmt.Errorf("redactions=%v", rs)
	}
	if !eqStr(rs[0]["masked"], "4111********1111") {
		return fmt.Errorf("masked=%v", rs[0]["masked"])
	}
	return nil
}

func scenarioBankCardBroken(c *client) error {
	text := "card 4111111111111112 end"
	code, body := c.post("/redact", map[string]any{"text": text})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	if !eqStr(body["text"], text) {
		return fmt.Errorf("text changed: %v", body["text"])
	}
	if len(redactionsOf(body)) != 0 {
		return fmt.Errorf("redactions=%v want empty", redactionsOf(body))
	}
	return nil
}

func scenarioOverlapEmailPhone(c *client) error {
	code, body := c.post("/redact", map[string]any{"text": "13812345678@example.com"})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	rs := redactionsOf(body)
	if len(rs) != 1 {
		return fmt.Errorf("redactions len=%d want 1: %v", len(rs), rs)
	}
	if !eqStr(rs[0]["type"], "email") {
		return fmt.Errorf("expected email to win, got %v", rs[0])
	}
	if !eqStr(body["text"], "1**********@example.com") {
		return fmt.Errorf("text=%v", body["text"])
	}
	return nil
}

func scenarioOverlapIDCardBankCard(c *client) error {
	id := findBothValid()
	code, body := c.post("/redact", map[string]any{"text": id})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	rs := redactionsOf(body)
	if len(rs) != 1 {
		return fmt.Errorf("redactions len=%d want 1 for %s: %v", len(rs), id, rs)
	}
	if !eqStr(rs[0]["type"], "idcard") {
		return fmt.Errorf("expected idcard to win over bankcard, got %v for %s", rs[0], id)
	}
	// idcard mask: keep first 6, last 4, mask middle 8.
	want := id[:6] + "********" + id[len(id)-4:]
	if !eqStr(body["text"], want) {
		return fmt.Errorf("text=%v want %v", body["text"], want)
	}
	return nil
}

func scenarioCustomMaskChar(c *client) error {
	code, body := c.post("/redact", map[string]any{"text": "13812345678", "mask_char": "#"})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	if !eqStr(body["text"], "138####5678") {
		return fmt.Errorf("text=%v", body["text"])
	}
	return nil
}

func scenarioNoPII(c *client) error {
	text := "just a normal sentence with no secrets"
	code, body := c.post("/redact", map[string]any{"text": text})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	if !eqStr(body["text"], text) {
		return fmt.Errorf("text changed: %v", body["text"])
	}
	rs := redactionsOf(body)
	if len(rs) != 0 {
		return fmt.Errorf("redactions=%v want empty", rs)
	}
	return nil
}

func scenarioMultipleEmails(c *client) error {
	code, body := c.post("/redact", map[string]any{"text": "a@b.com and c@d.com"})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	rs := redactionsOf(body)
	if len(rs) != 2 {
		return fmt.Errorf("redactions len=%d want 2", len(rs))
	}
	if !eqInt(rs[0]["start"], 0) || !eqInt(rs[1]["start"], 12) {
		return fmt.Errorf("offsets=%v", rs)
	}
	return nil
}

func scenarioPhoneInsideDigitRun(c *client) error {
	// A 16-digit Luhn-valid run whose first 11 digits look like a phone.
	// The phone is a substring of a longer digit run and must not be masked
	// separately; only the bank card span is reported.
	text := "1381234567800000"
	code, body := c.post("/redact", map[string]any{"text": text})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	rs := redactionsOf(body)
	if len(rs) != 1 {
		return fmt.Errorf("redactions len=%d want 1: %v", len(rs), rs)
	}
	if !eqStr(rs[0]["type"], "bankcard") {
		return fmt.Errorf("expected bankcard only, got %v", rs[0])
	}
	return nil
}

func scenarioChineseByteOffsets(c *client) error {
	// "联系" is 6 UTF-8 bytes; phone starts at byte 6.
	code, body := c.post("/redact", map[string]any{"text": "联系13812345678"})
	if code != http.StatusOK {
		return fmt.Errorf("code=%d body=%v", code, body)
	}
	rs := redactionsOf(body)
	if len(rs) != 1 || !eqStr(rs[0]["type"], "phone") {
		return fmt.Errorf("redactions=%v", rs)
	}
	if !eqInt(rs[0]["start"], 6) || !eqInt(rs[0]["end"], 17) {
		return fmt.Errorf("phone offsets=%v want [6,17)", rs[0])
	}
	return nil
}

func scenarioMissingText(c *client) error {
	code, body := c.post("/redact", map[string]any{"mask_char": "*"})
	if code != http.StatusBadRequest {
		return fmt.Errorf("code=%d want 400 body=%v", code, body)
	}
	if !strings.Contains(toStr(body["error"]), "text") {
		return fmt.Errorf("error=%v", body["error"])
	}
	return nil
}

func scenarioBadMaskChar(c *client) error {
	code, body := c.post("/redact", map[string]any{"text": "13812345678", "mask_char": "ab"})
	if code != http.StatusBadRequest {
		return fmt.Errorf("code=%d want 400 body=%v", code, body)
	}
	return nil
}

func scenarioBadJSON(c *client) error {
	code, _ := c.postRaw("/redact", []byte("{not json"))
	if code != http.StatusBadRequest {
		return fmt.Errorf("code=%d want 400", code)
	}
	return nil
}

func scenarioUnknownField(c *client) error {
	code, _ := c.postRaw("/redact", []byte(`{"text":"x","extra":1}`))
	if code != http.StatusBadRequest {
		return fmt.Errorf("code=%d want 400", code)
	}
	return nil
}

// findBothValid returns an 18-digit string that is both GB 11643 valid (with a
// digit check, not 'X') and Luhn valid, so idcard and bankcard detectors both
// match the same span and priority resolution must pick idcard.
func findBothValid() string {
	weights := [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	const check = "10X98765432"
	const prefix = "110105"
	for n := 0; n < 5_000_000; n++ {
		body := fmt.Sprintf("%s%011d", prefix, n) // 6 + 11 = 17 digits
		sum := 0
		for i := 0; i < 17; i++ {
			sum += int(body[i]-'0') * weights[i]
		}
		c := check[sum%11]
		if c == 'X' {
			continue
		}
		id := body + string(c)
		if luhnValidLocal(id) {
			return id
		}
	}
	return ""
}

// luhnValidLocal is a local copy of the Luhn check used only to seed the
// overlap test input; the authoritative implementation lives in package pii.
func luhnValidLocal(s string) bool {
	sum := 0
	for i := 0; i < len(s); i++ {
		d := int(s[len(s)-1-i] - '0')
		if i%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// toStr coerces a JSON-decoded value to a string for substring checks.
func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
