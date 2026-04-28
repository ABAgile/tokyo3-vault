package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Vault accepts a deliberately small subset of RFC 7644 §3.4.2.2 filters:
//
//	<attribute> eq "<value>"
//
// Allowed attributes:
//   - Users:  userName, externalId, id
//   - Groups: displayName, id
//
// Anything else (other operators, conjunctions, grouped expressions, or
// off-whitelist attributes) yields *scimFilterError so the caller can emit
// SCIM 400 with scimType:"invalidFilter". This subset is sufficient for
// Okta, Azure AD, and the auth outbound client.

type scimResourceKind int

const (
	scimResourceUser scimResourceKind = iota
	scimResourceGroup
)

type scimFilter struct {
	Attribute string
	Value     string
}

type scimFilterError struct{ msg string }

func (e *scimFilterError) Error() string { return e.msg }

// parseSCIMFilter returns (nil, nil) when the filter is empty (no filtering
// requested), (filter, nil) on a supported expression, and (nil, *scimFilterError)
// on anything outside the supported subset.
func parseSCIMFilter(raw string, kind scimResourceKind) (*scimFilter, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	opStart, valStart := findEqOperator(s)
	if opStart < 0 {
		return nil, &scimFilterError{"unsupported filter: only '<attr> eq \"value\"' is accepted"}
	}
	attr := strings.TrimSpace(s[:opStart])
	if attr == "" {
		return nil, &scimFilterError{"missing attribute"}
	}
	canon, ok := canonicalSCIMAttr(attr, kind)
	if !ok {
		return nil, &scimFilterError{"unsupported attribute: " + attr}
	}
	value, err := parseSCIMQuotedValue(strings.TrimSpace(s[valStart:]))
	if err != nil {
		return nil, err
	}
	return &scimFilter{Attribute: canon, Value: value}, nil
}

// findEqOperator returns the byte offsets of a standalone " eq " operator,
// or (-1, -1) if absent. "Standalone" means surrounded by whitespace on both
// sides — so "USERNAME eq " counts but "leq" or "eqx" do not.
func findEqOperator(s string) (start, valueStart int) {
	lower := strings.ToLower(s)
	from := 0
	for {
		idx := strings.Index(lower[from:], "eq")
		if idx < 0 {
			return -1, -1
		}
		i := from + idx
		end := i + 2
		if i == 0 || !isSCIMSpace(s[i-1]) {
			from = end
			continue
		}
		if end >= len(s) || !isSCIMSpace(s[end]) {
			from = end
			continue
		}
		return i, end + 1
	}
}

func isSCIMSpace(b byte) bool { return b == ' ' || b == '\t' }

func canonicalSCIMAttr(attr string, kind scimResourceKind) (string, bool) {
	switch strings.ToLower(attr) {
	case "id":
		return "id", true
	case "username":
		if kind == scimResourceUser {
			return "userName", true
		}
	case "externalid":
		if kind == scimResourceUser {
			return "externalId", true
		}
	case "displayname":
		if kind == scimResourceGroup {
			return "displayName", true
		}
	}
	return "", false
}

// parseSCIMQuotedValue uses encoding/json to parse the quoted string. json.Unmarshal
// requires the entire input to be a single valid JSON value, so trailing content
// (e.g. " and active eq true") fails — implicitly rejecting compound expressions.
func parseSCIMQuotedValue(s string) (string, error) {
	if len(s) == 0 {
		return "", &scimFilterError{"missing value"}
	}
	if s[0] != '"' {
		return "", &scimFilterError{"value must be a double-quoted string"}
	}
	var v string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", &scimFilterError{"invalid quoted string"}
	}
	return v, nil
}

// writeSCIMInvalidFilter emits the SCIM 400 + scimType:"invalidFilter" response
// per RFC 7644 §3.12.
func writeSCIMInvalidFilter(w http.ResponseWriter, detail string) {
	writeSCIMJSON(w, http.StatusBadRequest, map[string]any{
		"schemas":  []string{scimErrorSchema},
		"status":   http.StatusBadRequest,
		"scimType": "invalidFilter",
		"detail":   detail,
	})
}
