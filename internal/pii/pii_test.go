package pii

import (
	"fmt"
	"testing"
)

func TestGBValid(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"11010519491231002X", true},   // canonical valid ID
		{"11010519491231002x", true},   // lowercase x accepted
		{"123456789012345677", true},   // valid, check digit '7'
		{"110105194912310021", false},  // wrong check (should be X)
		{"123456789012345670", false},  // wrong check
		{"12345678901234567", false},   // too short (17)
		{"1234567890123456789", false}, // too long (19)
		{"1101051949123100X", false},   // digit position where digit expected
	}
	for _, c := range cases {
		if got := gbValid(c.s); got != c.want {
			t.Errorf("gbValid(%q)=%v want %v", c.s, got, c.want)
		}
	}
}

func TestLuhnValid(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"4111111111111111", true},  // Visa test number (16)
		{"4111111111111112", false}, // broken check digit
		{"79927398713", true},       // canonical Luhn example (13)
		{"79927398710", false},
		{"", false},
		{"4111a11111111111", false}, // non-digit rejected
	}
	for _, c := range cases {
		if got := luhnValid(c.s); got != c.want {
			t.Errorf("luhnValid(%q)=%v want %v", c.s, got, c.want)
		}
	}
}

func TestMaskSpan(t *testing.T) {
	cases := []struct {
		s, typ, mc, want string
	}{
		{"alice@example.com", TypeEmail, "*", "a****@example.com"},
		{"b@x.com", TypeEmail, "*", "b@x.com"},          // single-char local, nothing to mask
		{"13812345678", TypePhone, "*", "138****5678"},
		{"13812345678", TypePhone, "#", "138####5678"},
		{"11010519491231002X", TypeIDCard, "*", "110105********002X"},
		{"4111111111111111", TypeBankCard, "*", "4111********1111"},
		{"4242424242424242", TypeBankCard, "#", "4242########4242"},
	}
	for _, c := range cases {
		if got := maskSpan(c.s, c.typ, c.mc); got != c.want {
			t.Errorf("maskSpan(%q,%q,%q)=%q want %q", c.s, c.typ, c.mc, got, c.want)
		}
	}
}

func TestRedactEmailAndPhone(t *testing.T) {
	text := "contact alice@example.com or 13812345678"
	res := Redact(text, "")
	wantText := "contact a****@example.com or 138****5678"
	if res.Text != wantText {
		t.Errorf("text=%q want %q", res.Text, wantText)
	}
	if len(res.Redactions) != 2 {
		t.Fatalf("redactions=%v want 2", res.Redactions)
	}
	// email at byte 8, len 17 -> [8,25)
	em := res.Redactions[0]
	if em.Type != TypeEmail || em.Start != 8 || em.End != 25 || em.Masked != "a****@example.com" {
		t.Errorf("email redaction=%+v", em)
	}
	// phone at byte 29, len 11 -> [29,40)
	ph := res.Redactions[1]
	if ph.Type != TypePhone || ph.Start != 29 || ph.End != 40 || ph.Masked != "138****5678" {
		t.Errorf("phone redaction=%+v", ph)
	}
}

func TestRedactIDCardValidAndBroken(t *testing.T) {
	valid := "11010519491231002X"
	res := Redact(valid, "")
	if len(res.Redactions) != 1 || res.Redactions[0].Type != TypeIDCard {
		t.Fatalf("valid idcard: redactions=%v", res.Redactions)
	}
	if res.Text != "110105********002X" {
		t.Errorf("valid idcard text=%q", res.Text)
	}

	broken := "110105194912310021" // wrong check, also Luhn-invalid -> not masked
	res2 := Redact(broken, "")
	if res2.Text != broken || len(res2.Redactions) != 0 {
		t.Errorf("broken idcard: text=%q redactions=%v", res2.Text, res2.Redactions)
	}
}

func TestRedactBankCardValidAndBroken(t *testing.T) {
	valid := "4111111111111111"
	res := Redact(valid, "")
	if len(res.Redactions) != 1 || res.Redactions[0].Type != TypeBankCard {
		t.Fatalf("valid bankcard: redactions=%v", res.Redactions)
	}
	if res.Text != "4111********1111" {
		t.Errorf("valid bankcard text=%q", res.Text)
	}

	broken := "4111111111111112" // Luhn-invalid
	res2 := Redact(broken, "")
	if res2.Text != broken || len(res2.Redactions) != 0 {
		t.Errorf("broken bankcard: text=%q redactions=%v", res2.Text, res2.Redactions)
	}
}

func TestRedactOverlapEmailBeatsPhone(t *testing.T) {
	text := "13812345678@example.com" // phone [0,11) overlaps email [0,22)
	res := Redact(text, "")
	if len(res.Redactions) != 1 {
		t.Fatalf("redactions=%v want 1", res.Redactions)
	}
	r := res.Redactions[0]
	if r.Type != TypeEmail {
		t.Errorf("expected email to win, got %v", r)
	}
	if r.Masked != "1**********@example.com" {
		t.Errorf("masked=%q", r.Masked)
	}
	if res.Text != "1**********@example.com" {
		t.Errorf("text=%q", res.Text)
	}
}

func TestRedactBothValidIDCardWins(t *testing.T) {
	id := findBothValid(t) // 18 digits, GB-valid and Luhn-valid
	res := Redact(id, "")
	if len(res.Redactions) != 1 {
		t.Fatalf("redactions=%v want 1 for %s", res.Redactions, id)
	}
	r := res.Redactions[0]
	if r.Type != TypeIDCard {
		t.Errorf("expected idcard to win over bankcard, got %v for %s", r, id)
	}
	// idcard mask keeps first 6 and last 4.
	want := maskSpan(id, TypeIDCard, "*")
	if res.Text != want {
		t.Errorf("text=%q want %q", res.Text, want)
	}
}

func TestRedactCustomMaskChar(t *testing.T) {
	res := Redact("13812345678", "#")
	if res.Text != "138####5678" {
		t.Errorf("text=%q", res.Text)
	}
}

func TestRedactNoPII(t *testing.T) {
	text := "hello world, nothing sensitive here"
	res := Redact(text, "")
	if res.Text != text {
		t.Errorf("text changed: %q", res.Text)
	}
	if len(res.Redactions) != 0 {
		t.Errorf("redactions=%v want empty", res.Redactions)
	}
}

func TestRedactMultipleEmails(t *testing.T) {
	text := "a@b.com and c@d.com"
	res := Redact(text, "")
	if len(res.Redactions) != 2 {
		t.Fatalf("redactions=%v want 2", res.Redactions)
	}
	if res.Redactions[0].Start != 0 || res.Redactions[1].Start != 12 {
		t.Errorf("offsets=%v", res.Redactions)
	}
}

// findBothValid returns an 18-digit string that is both GB 11643 valid (with a
// digit, not 'X', check) and Luhn valid, so the idcard and bankcard detectors
// both match the same span and priority resolution must pick idcard.
func findBothValid(t *testing.T) string {
	t.Helper()
	const prefix = "110105"
	for n := 0; n < 5_000_000; n++ {
		body := fmt.Sprintf("%s%011d", prefix, n) // 6 + 11 = 17 digits
		sum := 0
		ok := true
		for i := 0; i < 17; i++ {
			sum += int(body[i]-'0') * gbWeights[i]
		}
		check := gbCheck[sum%11]
		if check == 'X' {
			ok = false
		}
		if !ok {
			continue
		}
		id := body + string(check)
		if luhnValid(id) {
			return id
		}
	}
	t.Fatal("no both-valid 18-digit number found")
	return ""
}
