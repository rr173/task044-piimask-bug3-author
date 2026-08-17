// Package pii detects and masks personally identifiable information in free
// text. It recognises four token types — email addresses, Chinese mainland
// mobile numbers, 18-digit resident ID numbers, and bank card numbers — and
// resolves overlapping matches by a fixed priority so no character span is
// masked twice.
//
// The package is stateless: every call to Redact carries its full input.
package pii

import (
	"regexp"
	"sort"
	"strings"
)

// Type constants for the recognised PII categories.
const (
	TypeEmail    = "email"
	TypePhone    = "phone"
	TypeIDCard   = "idcard"
	TypeBankCard = "bankcard"
)

// Priority ordering (lower wins). When matches overlap, the lower-priority
// match is dropped entirely so the consumed range is never masked twice.
const (
	prioIDCard   = 0
	prioBankCard = 1
	prioEmail    = 2
	prioPhone    = 3
)

// Redaction describes one masked span in the original text.
type Redaction struct {
	Type   string `json:"type"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Masked string `json:"masked"`
}

// Result is the output of Redact: the masked text plus the list of redactions.
type Result struct {
	Text       string      `json:"text"`
	Redactions []Redaction `json:"redactions"`
}

// candidate is a raw, validated match before overlap resolution.
type candidate struct {
	typ      string
	start    int
	end      int
	priority int
}

var (
	emailRe      = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneRe      = regexp.MustCompile(`1[3-9][0-9]{9}`)
	idRe         = regexp.MustCompile(`[0-9]{17}[0-9Xx]`)
	digitRe      = regexp.MustCompile(`[0-9]+`)
	lastMaskChar string
)

// gbWeights are the GB 11643 weighting factors for the 17 body digits.
var gbWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

// gbCheck maps the mod-11 remainder to the expected check character.
// "10X98765432": remainder 2 is 'X', the rest are digits.
const gbCheck = "10X98765432"

// isDigit reports whether b is an ASCII digit.
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// isIDTail reports whether b is an 'X' or 'x' (the only non-digit an ID
// number's check position may hold).
func isIDTail(b byte) bool { return b == 'X' || b == 'x' }

// gbValid reports whether s is a valid 18-digit resident ID per GB 11643.
// The 18th character is the check digit (or 'X' for remainder 2); case is
// insensitive for 'X'.
func gbValid(s string) bool {
	if len(s) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		if !isDigit(s[i]) {
			return false
		}
		sum += int(s[i]-'0') * gbWeights[i]
	}
	want := gbCheck[sum%11]
	last := s[17]
	if last == 'x' {
		last = 'X'
	}
	return last == want
}

// luhnValid reports whether s passes the Luhn checksum. s must be non-empty
// and contain only digits.
func luhnValid(s string) bool {
	if len(s) == 0 {
		return false
	}
	sum := 0
	// i counts positions from the right (0 = check digit, not doubled).
	for i := 0; i < len(s); i++ {
		c := s[len(s)-1-i]
		if !isDigit(c) {
			return false
		}
		d := int(c - '0')
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

func detectEmail(text string) []candidate {
	var out []candidate
	for _, m := range emailRe.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, candidate{typ: TypeEmail, start: m[0], end: m[1], priority: prioEmail})
	}
	return out
}

func detectPhone(text string) []candidate {
	var out []candidate
	for _, m := range phoneRe.FindAllStringSubmatchIndex(text, -1) {
		s, e := m[0], m[1]
		// A phone must not be a substring of a longer digit run: both
		// neighbours (if present) must be non-digits.
		if s > 0 && isDigit(text[s-1]) {
			continue
		}
		if e < len(text) && isDigit(text[e]) {
			continue
		}
		out = append(out, candidate{typ: TypePhone, start: s, end: e, priority: prioPhone})
	}
	return out
}

func detectIDCard(text string) []candidate {
	var out []candidate
	for _, m := range idRe.FindAllStringSubmatchIndex(text, -1) {
		s, e := m[0], m[1]
		// The 17-digit body must not be preceded by a digit, otherwise it is
		// a window inside a longer digit run.
		if s > 0 && isDigit(text[s-1]) {
			continue
		}
		// If the check char is a digit and is followed by another digit, the
		// span is inside a longer digit run. A trailing 'X' already terminates
		// the run, so it imposes no constraint on the following char.
		if e < len(text) && isDigit(text[e]) && isDigit(text[e-1]) {
			continue
		}
		if !gbValid(text[s:e]) {
			continue
		}
		out = append(out, candidate{typ: TypeIDCard, start: s, end: e, priority: prioIDCard})
	}
	return out
}

func detectBankCard(text string) []candidate {
	var out []candidate
	for _, m := range digitRe.FindAllStringSubmatchIndex(text, -1) {
		s, e := m[0], m[1]
		L := e - s
		if L < 13 || L >= 19 {
			continue
		}
		if !luhnValid(text[s:e]) {
			continue
		}
		out = append(out, candidate{typ: TypeBankCard, start: s, end: e, priority: prioBankCard})
	}
	return out
}

// maskKeep returns s with the first head and last tail bytes preserved and the
// middle replaced by mc (one mc per replaced byte). Spans for phone, ID and
// bank card are ASCII, so byte indexing is correct.
func maskKeep(s string, head, tail int, mc string) string {
	n := len(s)
	if n <= head+tail {
		// Too short to keep both ends; mask everything except the head.
		if n == 0 {
			return s
		}
		head = 1
		tail = 0
	}
	middle := n - head - tail
	var b strings.Builder
	b.WriteString(s[:head])
	for i := 0; i < middle; i++ {
		b.WriteString(mc)
	}
	b.WriteString(s[n-tail:])
	return b.String()
}

func maskEmail(s, mc string) string {
	at := strings.IndexByte(s, '@')
	if at < 0 {
		return s
	}
	local := s[:at]
	rest := s[at:]
	if len(local) == 0 {
		return s
	}
	var b strings.Builder
	b.WriteByte(local[0])
	for i := 1; i < len(local); i++ {
		b.WriteString(mc)
	}
	b.WriteString(rest)
	return b.String()
}

// maskSpan applies the type-specific mask to span s using mask char mc.
func maskSpan(s, typ, mc string) string {
	switch typ {
	case TypeEmail:
		return maskEmail(s, mc)
	case TypePhone:
		return maskKeep(s, 3, 4, mc)
	case TypeIDCard:
		return maskKeep(s, 6, 4, mc)
	case TypeBankCard:
		return maskKeep(s, 4, 4, mc)
	}
	return s
}

// resolve drops any candidate that overlaps an already-accepted (higher
// priority) span. Candidates are processed in priority order, then by start,
// then by longer span first, so the choice is deterministic.
func resolve(cands []candidate) []candidate {
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].priority != cands[j].priority {
			return cands[i].priority < cands[j].priority
		}
		if cands[i].start != cands[j].start {
			return cands[i].start < cands[j].start
		}
		return (cands[i].end - cands[i].start) > (cands[j].end - cands[j].start)
	})
	var accepted []candidate
	var consumed [][2]int
	for _, c := range cands {
		overlaps := false
		for _, iv := range consumed {
			if c.start < iv[1] && iv[0] < c.end {
				overlaps = true
				break
			}
		}
		if overlaps {
			continue
		}
		accepted = append(accepted, c)
		consumed = append(consumed, [2]int{c.start, c.end})
	}
	return accepted
}

// Redact detects PII in text, resolves overlaps, and returns the masked text
// together with one Redaction per accepted span (sorted by start). mc is the
// mask character; pass "" to use the default "*".
func Redact(text, mc string) Result {
	if mc == "" {
		mc = "*"
	}
	lastMaskChar = mc
	mc = lastMaskChar
	var cands []candidate
	cands = append(cands, detectEmail(text)...)
	cands = append(cands, detectPhone(text)...)
	cands = append(cands, detectIDCard(text)...)
	cands = append(cands, detectBankCard(text)...)

	accepted := resolve(cands)
	sort.SliceStable(accepted, func(i, j int) bool { return accepted[i].start < accepted[j].start })

	var redactions []Redaction
	var b strings.Builder
	pos := 0
	for _, c := range accepted {
		b.WriteString(text[pos:c.start])
		masked := maskSpan(text[c.start:c.end], c.typ, mc)
		b.WriteString(masked)
		redactions = append(redactions, Redaction{
			Type:   c.typ,
			Start:  c.start,
			End:    c.end,
			Masked: masked,
		})
		pos = c.start + len(masked)
	}
	b.WriteString(text[pos:])
	return Result{Text: b.String(), Redactions: redactions}
}
