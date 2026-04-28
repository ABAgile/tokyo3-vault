package api

import "testing"

func TestParseSCIMFilter_Empty(t *testing.T) {
	for _, raw := range []string{"", "   ", "\t"} {
		f, err := parseSCIMFilter(raw, scimResourceUser)
		if err != nil {
			t.Fatalf("empty filter %q: unexpected error %v", raw, err)
		}
		if f != nil {
			t.Fatalf("empty filter %q: expected nil filter, got %+v", raw, f)
		}
	}
}

func TestParseSCIMFilter_UserAttributes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		attr string
		val  string
	}{
		{"userName lower", `userName eq "alice@example.com"`, "userName", "alice@example.com"},
		{"userName upper", `USERNAME eq "alice@example.com"`, "userName", "alice@example.com"},
		{"externalId mixed", `externalId eq "abc-123"`, "externalId", "abc-123"},
		{"id", `id eq "00000000-0000-0000-0000-000000000001"`, "id", "00000000-0000-0000-0000-000000000001"},
		{"eq upper", `userName EQ "x@y"`, "userName", "x@y"},
		{"extra spaces", `  userName   eq   "x@y"  `, "userName", "x@y"},
		{"escaped quote in value", `userName eq "a\"b"`, "userName", `a"b`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parseSCIMFilter(tc.raw, scimResourceUser)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if f == nil {
				t.Fatalf("expected filter, got nil")
			}
			if f.Attribute != tc.attr {
				t.Errorf("attr = %q, want %q", f.Attribute, tc.attr)
			}
			if f.Value != tc.val {
				t.Errorf("value = %q, want %q", f.Value, tc.val)
			}
		})
	}
}

func TestParseSCIMFilter_GroupAttributes(t *testing.T) {
	f, err := parseSCIMFilter(`displayName eq "Engineering"`, scimResourceGroup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == nil || f.Attribute != "displayName" || f.Value != "Engineering" {
		t.Fatalf("unexpected result: %+v", f)
	}

	f, err = parseSCIMFilter(`id eq "abc"`, scimResourceGroup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == nil || f.Attribute != "id" || f.Value != "abc" {
		t.Fatalf("unexpected result: %+v", f)
	}
}

func TestParseSCIMFilter_RejectsOffWhitelistAttr(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		kind scimResourceKind
	}{
		{"email on user", `email eq "x@y"`, scimResourceUser},
		{"active on user", `active eq "true"`, scimResourceUser},
		{"displayName on user", `displayName eq "bob"`, scimResourceUser},
		{"userName on group", `userName eq "x"`, scimResourceGroup},
		{"externalId on group", `externalId eq "x"`, scimResourceGroup},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parseSCIMFilter(tc.raw, tc.kind)
			if err == nil {
				t.Fatalf("expected error, got filter %+v", f)
			}
			if _, ok := err.(*scimFilterError); !ok {
				t.Fatalf("expected *scimFilterError, got %T", err)
			}
		})
	}
}

func TestParseSCIMFilter_RejectsNonEqOperators(t *testing.T) {
	cases := []string{
		`userName co "alice"`,
		`userName sw "alice"`,
		`userName ew "@example.com"`,
		`userName ne "bob"`,
		`userName pr`,
		`userName gt "0"`,
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if f, err := parseSCIMFilter(raw, scimResourceUser); err == nil {
				t.Fatalf("expected error, got filter %+v", f)
			}
		})
	}
}

func TestParseSCIMFilter_RejectsCompound(t *testing.T) {
	cases := []string{
		`userName eq "a" and active eq true`,
		`userName eq "a" or id eq "b"`,
		`(userName eq "a")`,
		`not (userName eq "a")`,
		`userName eq "a" extra`,
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if f, err := parseSCIMFilter(raw, scimResourceUser); err == nil {
				t.Fatalf("expected error, got filter %+v", f)
			}
		})
	}
}

func TestParseSCIMFilter_RejectsMalformed(t *testing.T) {
	cases := []string{
		`userName eq`,
		`userName eq alice`,
		`eq "x"`,
		`userName "x"`,
		`"x" eq "y"`,
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if f, err := parseSCIMFilter(raw, scimResourceUser); err == nil {
				t.Fatalf("expected error, got filter %+v", f)
			}
		})
	}
}
