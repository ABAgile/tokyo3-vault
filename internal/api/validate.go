package api

import "net/http"

// validatePassword writes a 400 error and returns false when password is shorter
// than the minimum length. Centralises the repeated check across auth handlers.
func validatePassword(w http.ResponseWriter, password string) bool {
	if len(password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return false
	}
	return true
}
