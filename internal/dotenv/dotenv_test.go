package dotenv

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []Entry
		wantErr bool
	}{
		{
			name:  "simple unquoted",
			input: "FOO=bar\nBAZ=qux\n",
			want: []Entry{
				{Key: "FOO", Value: "bar"},
				{Key: "BAZ", Value: "qux"},
			},
		},
		{
			name:  "double quoted",
			input: `KEY="hello world"` + "\n",
			want:  []Entry{{Key: "KEY", Value: "hello world"}},
		},
		{
			name:  "single quoted",
			input: "KEY='hello world'\n",
			want:  []Entry{{Key: "KEY", Value: "hello world"}},
		},
		{
			name:  "export prefix stripped",
			input: "export KEY=value\n",
			want:  []Entry{{Key: "KEY", Value: "value"}},
		},
		{
			name:  "key lowercased to upper",
			input: "my_key=val\n",
			want:  []Entry{{Key: "MY_KEY", Value: "val"}},
		},
		{
			name:  "comment captured in next entry",
			input: "# comment\nKEY=val\n",
			want:  []Entry{{Comment: "# comment\n", Key: "KEY", Value: "val"}},
		},
		{
			name:  "blank line captured in next entry",
			input: "\nKEY=val\n",
			want:  []Entry{{Comment: "\n", Key: "KEY", Value: "val"}},
		},
		{
			name:  "multiple comment and blank lines",
			input: "# first\n\n# second\nKEY=val\n",
			want:  []Entry{{Comment: "# first\n\n# second\n", Key: "KEY", Value: "val"}},
		},
		{
			name:  "comment split between entries",
			input: "A=1\n# for B\nB=2\n",
			want: []Entry{
				{Key: "A", Value: "1"},
				{Comment: "# for B\n", Key: "B", Value: "2"},
			},
		},
		{
			name:  "double-quoted escape sequences",
			input: `KEY="line1\nline2\ttab"` + "\n",
			want:  []Entry{{Key: "KEY", Value: "line1\nline2\ttab"}},
		},
		{
			name:  "double-quoted escaped quote",
			input: `KEY="say \"hi\""` + "\n",
			want:  []Entry{{Key: "KEY", Value: `say "hi"`}},
		},
		{
			name:  "double-quoted escaped backslash",
			input: `KEY="path\\file"` + "\n",
			want:  []Entry{{Key: "KEY", Value: `path\file`}},
		},
		{
			name:  "single-quoted no escape expansion",
			input: `KEY='no\nexpand'` + "\n",
			want:  []Entry{{Key: "KEY", Value: `no\nexpand`}},
		},
		{
			name:  "empty value unquoted",
			input: "KEY=\n",
			want:  []Entry{{Key: "KEY", Value: ""}},
		},
		{
			name:  "empty value double quoted",
			input: `KEY=""` + "\n",
			want:  []Entry{{Key: "KEY", Value: ""}},
		},
		{
			name:  "windows line endings stripped",
			input: "KEY=val\r\n",
			want:  []Entry{{Key: "KEY", Value: "val"}},
		},
		{
			name:  "trailing comment without newline",
			input: "KEY=val",
			want:  []Entry{{Key: "KEY", Value: "val"}},
		},
		{
			name:    "missing equals sign",
			input:   "NOEQUALS\n",
			wantErr: true,
		},
		{
			name:    "empty key",
			input:   "=value\n",
			wantErr: true,
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "only comments and blanks",
			input: "# comment\n\n# another\n",
			want:  nil,
		},
		{
			name:  "value with equals sign",
			input: "KEY=a=b=c\n",
			want:  []Entry{{Key: "KEY", Value: "a=b=c"}},
		},
		{
			name:  "unquoted value trimmed",
			input: "KEY=  val  \n",
			want:  []Entry{{Key: "KEY", Value: "val"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len(entries) = %d, want %d\ngot:  %+v\nwant: %+v", len(got), len(tc.want), got, tc.want)
			}
			for i, e := range got {
				w := tc.want[i]
				if e.Key != w.Key {
					t.Errorf("[%d] Key = %q, want %q", i, e.Key, w.Key)
				}
				if e.Value != w.Value {
					t.Errorf("[%d] Value = %q, want %q", i, e.Value, w.Value)
				}
				if e.Comment != w.Comment {
					t.Errorf("[%d] Comment = %q, want %q", i, e.Comment, w.Comment)
				}
			}
		})
	}
}

func TestSerialize(t *testing.T) {
	tests := []struct {
		name    string
		entries []Entry
		want    string
	}{
		{
			name:    "empty",
			entries: nil,
			want:    "",
		},
		{
			name:    "simple",
			entries: []Entry{{Key: "FOO", Value: "bar"}},
			want:    "FOO=bar\n",
		},
		{
			name:    "empty value quoted",
			entries: []Entry{{Key: "KEY", Value: ""}},
			want:    `KEY=""` + "\n",
		},
		{
			name:    "value with space quoted",
			entries: []Entry{{Key: "KEY", Value: "hello world"}},
			want:    `KEY="hello world"` + "\n",
		},
		{
			name:    "comment preserved before key",
			entries: []Entry{{Comment: "# note\n", Key: "KEY", Value: "val"}},
			want:    "# note\nKEY=val\n",
		},
		{
			name: "multiple entries with comments",
			entries: []Entry{
				{Key: "A", Value: "1"},
				{Comment: "# for B\n", Key: "B", Value: "2"},
			},
			want: "A=1\n# for B\nB=2\n",
		},
		{
			name:    "newline in value escaped",
			entries: []Entry{{Key: "KEY", Value: "line1\nline2"}},
			want:    `KEY="line1\nline2"` + "\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Serialize(tc.entries)
			if got != tc.want {
				t.Errorf("Serialize() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRoundTrip verifies that Parse → Serialize → Parse produces identical entries.
func TestRoundTrip(t *testing.T) {
	inputs := []string{
		"FOO=bar\nBAZ=qux\n",
		"# comment\n\nKEY=val\n",
		"A=1\n# note\nB=2\n",
		`KEY="hello world"` + "\n",
		`KEY='single'` + "\n",
		"export KEY=value\n",
		"K=a=b=c\n",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			entries, err := Parse(input)
			if err != nil {
				t.Fatalf("first parse error: %v", err)
			}
			serialized := Serialize(entries)
			entries2, err := Parse(serialized)
			if err != nil {
				t.Fatalf("second parse error: %v", err)
			}
			if len(entries) != len(entries2) {
				t.Fatalf("entry count changed: %d → %d", len(entries), len(entries2))
			}
			for i := range entries {
				if entries[i].Key != entries2[i].Key {
					t.Errorf("[%d] Key changed: %q → %q", i, entries[i].Key, entries2[i].Key)
				}
				if entries[i].Value != entries2[i].Value {
					t.Errorf("[%d] Value changed: %q → %q", i, entries[i].Value, entries2[i].Value)
				}
			}
		})
	}
}

func TestNeedsQuoting(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"simple", false},
		{"with space", true},
		{"UPPER123", false},
		{"lower", false},
		{"with=equals", true},
		{"path/to/thing", false},
		{"user@host", false},
		{"key:value", false},
		{"a,b", false},
		{"has\nnewline", true},
		{"has\ttab", true},
		{"has\"quote", true},
		{"has'quote", true},
	}

	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			got := needsQuoting(tc.value)
			if got != tc.want {
				t.Errorf("needsQuoting(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}
