package finding

import (
	"fmt"
	"log/slog"
	"strconv"
	"unicode/utf8"
)

// Redact masks a credential for display. It keeps a short prefix because
// provider prefixes ("AKIA", "ghp_") are what responders need to route a
// revocation, and the length because it distinguishes key formats.
// Values shorter than 12 runes reveal nothing beyond their length.
func Redact(secret string) string {
	n := utf8.RuneCountInString(secret)
	if n < 12 {
		return "[REDACTED len=" + strconv.Itoa(n) + "]"
	}
	prefix := make([]rune, 0, 4)
	for _, r := range secret {
		if len(prefix) == 4 {
			break
		}
		prefix = append(prefix, r)
	}
	return string(prefix) + "…[REDACTED len=" + strconv.Itoa(n) + "]"
}

// Secret is a string that cannot be accidentally rendered in clear text. Every
// formatting path (fmt verbs, slog, JSON, text marshalling) emits the
// redacted form; Reveal is the only way to obtain the raw value.
type Secret string

// Reveal returns the raw value. Call sites should be limited to matchers and
// validators that must inspect the bytes.
func (s Secret) Reveal() string { return string(s) }

// String implements fmt.Stringer.
func (s Secret) String() string { return Redact(string(s)) }

// GoString implements fmt.GoStringer; without it %#v prints the raw value.
func (s Secret) GoString() string { return strconv.Quote(Redact(string(s))) }

// Format implements fmt.Formatter so that verbs which bypass String (%q, %x,
// %X) still emit the redacted form.
func (s Secret) Format(f fmt.State, verb rune) {
	r := Redact(string(s))
	switch verb {
	case 'q':
		fmt.Fprint(f, strconv.Quote(r))
	case 'v':
		if f.Flag('#') {
			fmt.Fprint(f, s.GoString())
			return
		}
		fmt.Fprint(f, r)
	default:
		fmt.Fprint(f, r)
	}
}

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(Redact(string(s))) }

// MarshalText implements encoding.TextMarshaler, covering JSON and YAML.
func (s Secret) MarshalText() ([]byte, error) { return []byte(Redact(string(s))), nil }
