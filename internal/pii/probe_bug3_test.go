package pii

import "testing"

func TestProbeNineteenDigitLuhnCardIsRedacted(t *testing.T) {
	const card = "4000000000000000006"
	got := Redact("card="+card, "")
	if len(got.Redactions) != 1 || got.Redactions[0].Type != TypeBankCard {
		t.Fatalf("redactions=%+v want one bankcard", got.Redactions)
	}
	if got.Text != "card=4000***********0006" {
		t.Fatalf("text=%q want %q", got.Text, "card=4000***********0006")
	}
}
