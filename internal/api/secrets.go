package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	lcrypto "github.com/abagile/tokyo3-lcl/crypto"
	"github.com/abagile/tokyo3-vault/internal/envfile"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
)

// pruneVersions removes old versions of a secret after a new one is written.
// Errors are logged and swallowed — pruning is best-effort and must not fail the write.
func (s *Server) pruneVersions(ctx context.Context, sv *model.SecretVersion) {
	count := s.pruneMinCount
	if count == 0 {
		count = defaultPruneMinCount
	}
	age := s.pruneMinAge
	if age == 0 {
		age = defaultPruneMinAge
	}
	cutoff := time.Now().UTC().Add(-age)
	if err := s.store.PruneSecretVersions(ctx, sv.SecretID, sv.ID, count, cutoff); err != nil {
		s.log.Warn("prune secret versions", "secret_id", sv.SecretID, "err", err)
	}
}

var keyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// maskValue returns the first 3 characters of v followed by "...", or just "..."
// for values shorter than 3 characters. Used in audit log metadata.
func maskValue(v string) string {
	const n = 3
	if len(v) <= n {
		return "..."
	}
	return v[:n] + "..."
}

// secretAuditMeta builds the JSON metadata string for secret audit entries.
func secretAuditMeta(maskedValue string) string {
	b, _ := json.Marshal(map[string]string{"value": maskedValue})
	return string(b)
}

type secretResponse struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
}

type secretMeta struct {
	Key       string `json:"key"`
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
}

type setSecretRequest struct {
	Value string `json:"value"`
}

type versionResponse struct {
	ID        string  `json:"id"`
	Version   int     `json:"version"`
	CreatedAt string  `json:"created_at"`
	CreatedBy *string `json:"created_by,omitempty"`
}

// resolveProjectEnv looks up project + environment from path values and enforces
// token scope. Returns the full Project so callers can access EncryptedPEK.
func (s *Server) resolveProjectEnv(r *http.Request, w http.ResponseWriter) (project *model.Project, envID string, ok bool) {
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "project not found")
		return nil, "", false
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, "", false
	}
	e, err := s.store.GetEnvironment(r.Context(), p.ID, r.PathValue("env"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "environment not found")
		return nil, "", false
	}
	if err != nil {
		s.log.Error("get env", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, "", false
	}
	if !s.authorize(w, r, tokenFromCtx(r), p.ID, e.ID) {
		return nil, "", false
	}
	return p, e.ID, true
}

// resolveProject looks up a project from the {project} path value.
func (s *Server) resolveProject(r *http.Request, w http.ResponseWriter) (*model.Project, bool) {
	p, err := s.store.GetProject(r.Context(), r.PathValue("project"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "project not found")
		return nil, false
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	return p, true
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	secrets, versions, err := s.store.ListSecrets(r.Context(), project.ID, envID)
	if err != nil {
		s.log.Error("list secrets", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]secretMeta, 0, len(secrets))
	for i, sec := range secrets {
		item := secretMeta{Key: sec.Key, UpdatedAt: fmtAPITime(sec.UpdatedAt)}
		if versions[i] != nil {
			item.Version = versions[i].Version
		}
		resp = append(resp, item)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	key := strings.ToUpper(r.PathValue("key"))
	sec, sv, err := s.store.GetSecret(r.Context(), project.ID, envID, key)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		s.log.Error("get secret", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if sv == nil {
		writeError(w, http.StatusNotFound, "secret has no versions")
		return
	}
	projectKP, err := s.projectKP.ForProject(r.Context(), project.ID, project.EncryptedPEK)
	if err != nil {
		s.log.Error("load project key", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	plaintext, err := lcrypto.DecryptEnvelope(r.Context(), projectKP, sv.EncryptedDEK, sv.EncryptedValue)
	if err != nil {
		s.log.Error("decrypt secret", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAuditEnv(r, ActionSecretGet, project.ID, envID, sec.Key, secretAuditMeta(maskValue(string(plaintext)))); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusOK, secretResponse{
		Key:       sec.Key,
		Value:     string(plaintext),
		Version:   sv.Version,
		UpdatedAt: fmtAPITime(sec.UpdatedAt),
	})
}

func (s *Server) handleSetSecret(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	key := strings.ToUpper(r.PathValue("key"))
	if key == "" {
		// POST to /secrets — key comes from body
		var body struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		key = strings.ToUpper(strings.TrimSpace(body.Key))
		if key == "" {
			writeError(w, http.StatusBadRequest, "key is required")
			return
		}
		if !keyRe.MatchString(key) {
			writeError(w, http.StatusBadRequest, "key must be uppercase alphanumeric with underscores")
			return
		}
		s.writeSetSecret(w, r, project, envID, key, body.Value)
		return
	}
	// PUT to /secrets/{key}
	if !keyRe.MatchString(key) {
		writeError(w, http.StatusBadRequest, "key must be uppercase alphanumeric with underscores")
		return
	}
	var req setSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.writeSetSecret(w, r, project, envID, key, req.Value)
}

func (s *Server) writeSetSecret(w http.ResponseWriter, r *http.Request, project *model.Project, envID, key, value string) {
	tok := tokenFromCtx(r)
	if !s.requireWrite(w, r, tok, project.ID) {
		return
	}
	sv, err := s.upsertSecret(r, project, envID, key, nil, value, tokenCreatedBy(tok), "")
	if err != nil {
		s.log.Error("upsert secret", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, versionResponse{
		ID:        sv.ID,
		Version:   sv.Version,
		CreatedAt: fmtAPITime(sv.CreatedAt),
		CreatedBy: sv.CreatedBy,
	})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	if !s.requireWrite(w, r, tokenFromCtx(r), project.ID) {
		return
	}
	key := strings.ToUpper(r.PathValue("key"))
	err := s.store.DeleteSecret(r.Context(), project.ID, envID, key)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		s.log.Error("delete secret", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.logAuditEnv(r, ActionSecretDelete, project.ID, envID, key, ""); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSecretVersions(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	key := strings.ToUpper(r.PathValue("key"))
	sec, _, err := s.store.GetSecret(r.Context(), project.ID, envID, key)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		s.log.Error("get secret", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	versions, err := s.store.ListSecretVersions(r.Context(), sec.ID)
	if err != nil {
		s.log.Error("list versions", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	resp := make([]versionResponse, 0, len(versions))
	for _, sv := range versions {
		resp = append(resp, versionToResponse(sv))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRollbackSecret(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	if !s.requireWrite(w, r, tokenFromCtx(r), project.ID) {
		return
	}
	key := strings.ToUpper(r.PathValue("key"))

	sec, _, err := s.store.GetSecret(r.Context(), project.ID, envID, key)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		s.log.Error("get secret", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var body struct {
		VersionID string `json:"version_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.VersionID == "" {
		writeError(w, http.StatusBadRequest, "version_id is required")
		return
	}

	sv, err := s.store.GetSecretVersion(r.Context(), sec.ID, body.VersionID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "version not found for this secret")
		return
	}
	if err != nil {
		s.log.Error("get secret version", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	newSV, err := s.store.RollbackSecret(r.Context(), sec.ID, body.VersionID, tokenCreatedBy(tokenFromCtx(r)))
	if err != nil {
		s.log.Error("rollback secret", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.pruneVersions(r.Context(), newSV)
	if err := s.logAuditEnv(r, ActionSecretRollback, project.ID, envID, key, fmt.Sprintf(`{"from_version":%d}`, sv.Version)); err != nil {
		writeError(w, http.StatusInternalServerError, "audit unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key":          key,
		"version_id":   newSV.ID,
		"version":      newSV.Version,
		"from_version": sv.Version,
	})
}

type importRequest struct {
	FromProject string   `json:"from_project"`
	FromEnv     string   `json:"from_env"`
	Overwrite   bool     `json:"overwrite"`
	Keys        []string `json:"keys"` // empty = all keys
}

func (s *Server) handleImportSecrets(w http.ResponseWriter, r *http.Request) {
	dstProject, dstEnvID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	if !s.requireWrite(w, r, tokenFromCtx(r), dstProject.ID) {
		return
	}

	var req importRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.FromProject == "" || req.FromEnv == "" {
		writeError(w, http.StatusBadRequest, "from_project and from_env are required")
		return
	}

	// Resolve source project + env and verify token has access.
	srcProject, srcEnvID, ok2 := s.resolveSrcProjectEnv(w, r, req.FromProject, req.FromEnv)
	if !ok2 {
		return
	}

	srcSecrets, srcVersions, err := s.store.ListSecrets(r.Context(), srcProject.ID, srcEnvID)
	if err != nil {
		s.log.Error("list src secrets", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Load both project KPs once up front.
	srcKP, err := s.projectKP.ForProject(r.Context(), srcProject.ID, srcProject.EncryptedPEK)
	if err != nil {
		s.log.Error("load src project key", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	dstKP, err := s.projectKP.ForProject(r.Context(), dstProject.ID, dstProject.EncryptedPEK)
	if err != nil {
		s.log.Error("load dst project key", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	keyFilter := make(map[string]bool, len(req.Keys))
	for _, k := range req.Keys {
		keyFilter[strings.ToUpper(k)] = true
	}

	createdBy := tokenCreatedBy(tokenFromCtx(r))
	imported, skipped, importErr := s.importSecretsList(r, srcSecrets, srcVersions, keyFilter, srcKP, dstProject.ID, dstEnvID, dstKP, createdBy, req.Overwrite)
	if importErr != nil {
		writeError(w, http.StatusInternalServerError, importErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"imported": imported,
		"skipped":  skipped,
	})
}

// inKeyFilter reports whether key should be copied. An empty filter means "all keys".
func inKeyFilter(filter map[string]bool, key string) bool {
	return len(filter) == 0 || filter[key]
}

// importSecretsList iterates srcSecrets, applies the key filter, and copies
// eligible secrets to the destination. Returns (imported, skipped, error).
func (s *Server) importSecretsList(r *http.Request, srcSecrets []*model.Secret, srcVersions []*model.SecretVersion, keyFilter map[string]bool, srcKP lcrypto.KeyProvider, dstProjectID, dstEnvID string, dstKP lcrypto.KeyProvider, createdBy *string, overwrite bool) (imported, skipped int, err error) {
	for i, sec := range srcSecrets {
		if !inKeyFilter(keyFilter, sec.Key) {
			continue
		}
		if srcVersions[i] == nil {
			continue
		}
		did, copyErr := s.copySecret(r, sec, srcVersions[i], srcKP, dstProjectID, dstEnvID, dstKP, createdBy, overwrite)
		if copyErr != nil {
			return imported, skipped, copyErr
		}
		if did {
			imported++
		} else {
			skipped++
		}
	}
	return imported, skipped, nil
}

// tokenCreatedBy returns the best identifier of who issued tok: the user ID
// for user session tokens (portal sign-ins, `vault login`), or the token ID
// for machine tokens (no UserID set). Returns nil when tok is nil. Used as
// the created_by stamp on secret versions and dynamic leases — the display
// layer resolves user IDs to emails via GetUserByID.
func tokenCreatedBy(tok *model.Token) *string {
	if tok == nil {
		return nil
	}
	if tok.UserID != nil {
		return tok.UserID
	}
	return &tok.ID
}

// resolveSrcProjectEnv looks up the source project and environment for an
// import request, writes an HTTP error and returns false on any failure.
func (s *Server) resolveSrcProjectEnv(w http.ResponseWriter, r *http.Request, fromProject, fromEnv string) (project *model.Project, envID string, ok bool) {
	srcProject, err := s.store.GetProject(r.Context(), fromProject)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "source project not found")
		return nil, "", false
	}
	if err != nil {
		s.log.Error("get src project", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, "", false
	}
	srcEnv, err := s.store.GetEnvironment(r.Context(), srcProject.ID, fromEnv)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "source environment not found")
		return nil, "", false
	}
	if err != nil {
		s.log.Error("get src env", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, "", false
	}
	if !s.authorize(w, r, tokenFromCtx(r), srcProject.ID, srcEnv.ID) {
		return nil, "", false
	}
	return srcProject, srcEnv.ID, true
}

// copySecret decrypts one source secret and writes it to the destination env.
// Returns (true, nil) when written, (false, nil) when skipped (already exists
// and overwrite is false), or (false, err) on failure.
func (s *Server) copySecret(r *http.Request, sec *model.Secret, sv *model.SecretVersion, srcKP lcrypto.KeyProvider, dstProjectID, dstEnvID string, dstKP lcrypto.KeyProvider, createdBy *string, overwrite bool) (bool, error) {
	if !overwrite {
		if _, _, err := s.store.GetSecret(r.Context(), dstProjectID, dstEnvID, sec.Key); err == nil {
			return false, nil
		}
	}
	plaintext, err := lcrypto.DecryptEnvelope(r.Context(), srcKP, sv.EncryptedDEK, sv.EncryptedValue)
	if err != nil {
		s.log.Error("decrypt src secret", "key", sec.Key, "err", err)
		return false, fmt.Errorf("failed to decrypt source secret %s", sec.Key)
	}
	encVal, encDEK, err := lcrypto.EncryptEnvelope(r.Context(), dstKP, plaintext)
	if err != nil {
		s.log.Error("encrypt dst secret", "key", sec.Key, "err", err)
		return false, fmt.Errorf("internal error")
	}
	comment := sec.Comment
	newSV, err := s.store.SetSecret(r.Context(), dstProjectID, dstEnvID, sec.Key, &comment, encVal, encDEK, createdBy)
	if err != nil {
		s.log.Error("set dst secret", "key", sec.Key, "err", err)
		return false, fmt.Errorf("internal error")
	}
	s.pruneVersions(r.Context(), newSV)
	if err := s.logAuditEnv(r, ActionSecretImport, dstProjectID, dstEnvID, sec.Key, secretAuditMeta(maskValue(string(plaintext)))); err != nil {
		return false, err
	}
	return true, nil
}

func versionToResponse(sv *model.SecretVersion) versionResponse {
	return versionResponse{
		ID:        sv.ID,
		Version:   sv.Version,
		CreatedAt: fmtAPITime(sv.CreatedAt),
		CreatedBy: sv.CreatedBy,
	}
}

// handleUploadEnvfile parses a raw .env file body and upserts its secrets.
// Comments and blank lines preceding each key are stored alongside it.
// Query param: overwrite=true skips the duplicate check (default: skip existing).
func (s *Server) handleUploadEnvfile(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	tok := tokenFromCtx(r)
	if !s.requireWrite(w, r, tok, project.ID) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	overwrite := r.URL.Query().Get("overwrite") == "true"
	uploaded, skipped, err := s.uploadEnvfileBytes(r, project, envID, body, overwrite, tokenCreatedBy(tok))
	if err != nil {
		switch {
		case errors.Is(err, errInvalidEnvfile):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, errInvalidKey):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			s.log.Error("upload envfile", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uploaded": uploaded, "skipped": skipped})
}

// handleDownloadEnvfile decrypts all secrets for a project+env and returns them
// as a plain-text .env file, preserving insertion order and stored comments.
func (s *Server) handleDownloadEnvfile(w http.ResponseWriter, r *http.Request) {
	project, envID, ok := s.resolveProjectEnv(r, w)
	if !ok {
		return
	}
	content, err := s.renderEnvfile(r, project, envID)
	if err != nil {
		s.log.Error("download envfile", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
}

// errInvalidEnvfile / errInvalidKey wrap the parse-stage and key-validation
// errors from uploadEnvfileBytes so callers can distinguish 400-class issues
// from internal failures.
var (
	errInvalidEnvfile = errors.New("invalid .env file")
	errInvalidKey     = errors.New("invalid key")
)

// upsertSecret encrypts value, creates a new version via SetSecret, prunes old
// versions, and audits as secret.set. Caller handles authorization and the
// HTTP response. auditMeta is passed verbatim to logAuditEnv — pass "" for the
// JSON path's existing no-meta behaviour, or secretAuditMeta(maskValue(value))
// to record a masked preview (matches the envfile-upload audit shape).
func (s *Server) upsertSecret(r *http.Request, project *model.Project, envID, key string, comment *string, value string, createdBy *string, auditMeta string) (*model.SecretVersion, error) {
	projectKP, err := s.projectKP.ForProject(r.Context(), project.ID, project.EncryptedPEK)
	if err != nil {
		return nil, fmt.Errorf("load project key: %w", err)
	}
	encVal, encDEK, err := lcrypto.EncryptEnvelope(r.Context(), projectKP, []byte(value))
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	sv, err := s.store.SetSecret(r.Context(), project.ID, envID, key, comment, encVal, encDEK, createdBy)
	if err != nil {
		return nil, fmt.Errorf("set secret: %w", err)
	}
	s.pruneVersions(r.Context(), sv)
	if err := s.logAuditEnv(r, ActionSecretSet, project.ID, envID, key, auditMeta); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return sv, nil
}

// decryptSecretVersion loads the project's PEK and decrypts a specific secret
// version's value. Caller is responsible for authorization and audit logging.
func (s *Server) decryptSecretVersion(ctx context.Context, project *model.Project, sv *model.SecretVersion) ([]byte, error) {
	projectKP, err := s.projectKP.ForProject(ctx, project.ID, project.EncryptedPEK)
	if err != nil {
		return nil, fmt.Errorf("load project key: %w", err)
	}
	plaintext, err := lcrypto.DecryptEnvelope(ctx, projectKP, sv.EncryptedDEK, sv.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// uploadEnvfileBytes parses a raw .env body and upserts its secrets. Audits
// each upserted key and prunes old versions. Wraps errInvalidEnvfile or
// errInvalidKey on parse / validation failures so callers can map to 400.
func (s *Server) uploadEnvfileBytes(r *http.Request, project *model.Project, envID string, body []byte, overwrite bool, createdBy *string) (uploaded, skipped int, err error) {
	entries, parseErr := envfile.Parse(string(body))
	if parseErr != nil {
		return 0, 0, fmt.Errorf("%w: %v", errInvalidEnvfile, parseErr)
	}
	projectKP, err := s.projectKP.ForProject(r.Context(), project.ID, project.EncryptedPEK)
	if err != nil {
		return 0, 0, fmt.Errorf("load project key: %w", err)
	}
	for _, entry := range entries {
		if !keyRe.MatchString(entry.Key) {
			return uploaded, skipped, fmt.Errorf("%w: %s", errInvalidKey, entry.Key)
		}
		if !overwrite {
			if _, _, err := s.store.GetSecret(r.Context(), project.ID, envID, entry.Key); err == nil {
				skipped++
				continue
			}
		}
		encVal, encDEK, encErr := lcrypto.EncryptEnvelope(r.Context(), projectKP, []byte(entry.Value))
		if encErr != nil {
			return uploaded, skipped, fmt.Errorf("encrypt %s: %w", entry.Key, encErr)
		}
		comment := entry.Comment
		sv, setErr := s.store.SetSecret(r.Context(), project.ID, envID, entry.Key, &comment, encVal, encDEK, createdBy)
		if setErr != nil {
			return uploaded, skipped, fmt.Errorf("set secret %s: %w", entry.Key, setErr)
		}
		s.pruneVersions(r.Context(), sv)
		if auditErr := s.logAuditEnv(r, ActionSecretEnvfileUpload, project.ID, envID, entry.Key, secretAuditMeta(maskValue(entry.Value))); auditErr != nil {
			return uploaded, skipped, fmt.Errorf("audit %s: %w", entry.Key, auditErr)
		}
		uploaded++
	}
	return uploaded, skipped, nil
}

// renderEnvfile decrypts every secret for project+env, audits each, and returns
// the serialised .env content. Callers handle the response headers + body.
func (s *Server) renderEnvfile(r *http.Request, project *model.Project, envID string) (string, error) {
	secrets, versions, err := s.store.ListSecrets(r.Context(), project.ID, envID)
	if err != nil {
		return "", fmt.Errorf("list secrets: %w", err)
	}
	projectKP, err := s.projectKP.ForProject(r.Context(), project.ID, project.EncryptedPEK)
	if err != nil {
		return "", fmt.Errorf("load project key: %w", err)
	}
	entries := make([]envfile.Entry, 0, len(secrets))
	for i, sec := range secrets {
		sv := versions[i]
		if sv == nil {
			continue
		}
		plaintext, err := lcrypto.DecryptEnvelope(r.Context(), projectKP, sv.EncryptedDEK, sv.EncryptedValue)
		if err != nil {
			return "", fmt.Errorf("decrypt %s: %w", sec.Key, err)
		}
		if err := s.logAuditEnv(r, ActionSecretEnvfileDownload, project.ID, envID, sec.Key, secretAuditMeta(maskValue(string(plaintext)))); err != nil {
			return "", fmt.Errorf("audit %s: %w", sec.Key, err)
		}
		entries = append(entries, envfile.Entry{
			Comment: sec.Comment,
			Key:     sec.Key,
			Value:   string(plaintext),
		})
	}
	return envfile.Serialize(entries), nil
}
