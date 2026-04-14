// Package dotenv parses and serializes .env files while preserving comments
// and blank lines that precede each key.
package dotenv

import (
	"fmt"
	"strings"
)

// Entry represents a single key=value pair from a .env file together with
// the raw text (comment lines and blank lines) that immediately precedes it
// in the file, since the previous key or the start of the file.
type Entry struct {
	Comment string // raw preceding text including trailing newline characters
	Key     string // always upper-cased on parse
	Value   string
}

// Parse parses the contents of a .env file into a slice of entries.
// Blank lines and comment lines are captured in the Comment field of the
// next key entry so that Serialize reproduces them faithfully.
//
// Supported syntax:
//
//	KEY=value
//	KEY="double quoted"
//	KEY='single quoted'
//	export KEY=value        (export prefix stripped)
//	# comment lines
//	(blank lines)
func Parse(content string) ([]Entry, error) {
	var entries []Entry
	var pending strings.Builder

	lines := strings.Split(content, "\n")
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)

		// Blank or comment-only line — buffer for next key.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			pending.WriteString(line + "\n")
			continue
		}

		// Strip optional "export " prefix.
		active := trimmed
		if strings.HasPrefix(active, "export ") {
			active = strings.TrimSpace(active[7:])
		}

		before, after, ok := strings.Cut(active, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing '=' in %q", i+1, line)
		}

		key := strings.TrimSpace(before)
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", i+1)
		}

		value := unquote(after)

		entries = append(entries, Entry{
			Comment: pending.String(),
			Key:     strings.ToUpper(key),
			Value:   value,
		})
		pending.Reset()
	}

	return entries, nil
}

// Serialize formats a slice of entries back into a .env file string.
// Each entry's Comment field is emitted verbatim, followed by KEY=value.
func Serialize(entries []Entry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Comment)
		b.WriteString(e.Key)
		b.WriteByte('=')
		b.WriteString(quote(e.Value))
		b.WriteByte('\n')
	}
	return b.String()
}

// unquote removes surrounding single or double quotes from a value.
// For double-quoted values, basic escape sequences (\n \t \\ \") are expanded.
// Unquoted values are returned trimmed of leading/trailing whitespace.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	q := s[0]
	if (q == '"' || q == '\'') && s[len(s)-1] == q {
		inner := s[1 : len(s)-1]
		if q == '"' {
			inner = strings.ReplaceAll(inner, `\\`, "\x00") // protect escaped backslash
			inner = strings.ReplaceAll(inner, `\"`, `"`)
			inner = strings.ReplaceAll(inner, `\n`, "\n")
			inner = strings.ReplaceAll(inner, `\t`, "\t")
			inner = strings.ReplaceAll(inner, "\x00", `\`)
		}
		return inner
	}
	return s
}

// quote wraps the value in double quotes when it contains characters that
// would be ambiguous in a plain .env file (spaces, quotes, newlines, etc.).
// Simple alphanumeric-ish values are left unquoted.
func quote(s string) string {
	if s == "" {
		return `""`
	}
	if !needsQuoting(s) {
		return s
	}
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, "\n", `\n`)
	escaped = strings.ReplaceAll(escaped, "\t", `\t`)
	return `"` + escaped + `"`
}

// safeChars lists every character that can appear unquoted in a .env value.
const safeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-./:+@%,~"

func needsQuoting(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune(safeChars, r) {
			return true
		}
	}
	return false
}
