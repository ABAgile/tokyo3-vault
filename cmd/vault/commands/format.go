package commands

import "time"

// fmtTime parses a UTC timestamp returned by the API and reformats it in the
// process's local timezone (as set by the TZ environment variable or the
// system default). Falls back to UTC if the local zone is not configured, and
// returns the raw string if parsing fails entirely.
func fmtTime(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}
