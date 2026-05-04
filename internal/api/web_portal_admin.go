package api

import (
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-vault/internal/auth"
	"github.com/abagile/tokyo3-vault/internal/model"
	"github.com/abagile/tokyo3-vault/internal/store"
	"github.com/google/uuid"
)

// ── Admin: Users ──────────────────────────────────────────────────────────────

func (s *Server) handlePortalAdminUsers(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "list users failed", http.StatusInternalServerError)
		return
	}
	s.portalTmpl.render(w, "portal_admin_users.html", struct {
		portalBase
		Users          []*model.User
		Success, Error string
	}{newPortalBase(pc, "admin-users"), users,
		r.URL.Query().Get("success"), r.URL.Query().Get("error")})
}

func (s *Server) handlePortalAdminUserNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if r.Method == http.MethodGet {
		s.portalTmpl.render(w, "portal_admin_user_edit.html", struct {
			portalBase
			User           *model.User
			IsNew          bool
			Error, Success string
		}{newPortalBase(pc, "admin-users"),
			&model.User{Role: model.UserRoleMember, Active: true}, true, "", ""})
		return
	}
	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")
	role := r.FormValue("role")

	showErr := func(msg string) {
		s.portalTmpl.render(w, "portal_admin_user_edit.html", struct {
			portalBase
			User           *model.User
			IsNew          bool
			Error, Success string
		}{newPortalBase(pc, "admin-users"),
			&model.User{Email: email, Role: role, Active: true}, true, msg, ""})
	}
	if email == "" || password == "" {
		showErr("Email and password are required.")
		return
	}
	if !validatePortalPassword(password) {
		showErr("Password must be at least 12 characters.")
		return
	}
	if role != model.UserRoleAdmin && role != model.UserRoleMember {
		showErr("Role must be member or admin.")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.log.Error("hash password", "err", err)
		showErr("Create failed.")
		return
	}
	user, err := s.store.CreateUser(r.Context(), email, hash, role)
	if errors.Is(err, store.ErrConflict) {
		showErr("A user with that email already exists.")
		return
	}
	if err != nil {
		s.log.Error("create user", "err", err)
		showErr("Create failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionUserCreate, "", "", user.Email, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/users", "success", "User created.")
}

func (s *Server) handlePortalAdminUserEdit(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	user, err := s.store.GetUserByID(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	s.portalTmpl.render(w, "portal_admin_user_edit.html", struct {
		portalBase
		User           *model.User
		IsNew          bool
		Error, Success string
	}{newPortalBase(pc, "admin-users"), user, false,
		r.URL.Query().Get("error"), r.URL.Query().Get("success")})
}

func (s *Server) handlePortalAdminUserSetActive(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id := r.PathValue("id")
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		flashRedirect(w, r, "/portal/admin/users", "error", "User not found.")
		return
	}
	if user.ID == pc.User.ID {
		flashRedirect(w, r, "/portal/admin/users/"+id+"/edit", "error", "You cannot deactivate yourself.")
		return
	}
	_ = r.ParseForm()
	active := r.FormValue("active") == "1"
	if err := s.store.SetUserActive(r.Context(), id, active); err != nil {
		s.log.Error("set user active", "err", err)
		flashRedirect(w, r, "/portal/admin/users/"+id+"/edit", "error", "Update failed.")
		return
	}
	if !active {
		// Match the SCIM-side semantics: deactivation revokes all tokens.
		if err := s.store.DeleteAllTokensForUser(r.Context(), id); err != nil {
			s.log.Error("revoke tokens after deactivate", "err", err)
		}
	}
	if err := s.logAuditEnv(r, ActionUserSetActive, "", "", user.Email, portalMeta(map[string]any{"active": active})); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flash := "User reactivated."
	if !active {
		flash = "User deactivated and tokens revoked."
	}
	flashRedirect(w, r, "/portal/admin/users/"+id+"/edit", "success", flash)
}

func (s *Server) handlePortalAdminUserResetPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		flashRedirect(w, r, "/portal/admin/users", "error", "User not found.")
		return
	}
	_ = r.ParseForm()
	pw := r.FormValue("password")
	if !validatePortalPassword(pw) {
		flashRedirect(w, r, "/portal/admin/users/"+id+"/edit", "error", "Password must be at least 12 characters.")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.log.Error("hash password", "err", err)
		flashRedirect(w, r, "/portal/admin/users/"+id+"/edit", "error", "Reset failed.")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), id, hash); err != nil {
		s.log.Error("update password", "err", err)
		flashRedirect(w, r, "/portal/admin/users/"+id+"/edit", "error", "Reset failed.")
		return
	}
	if err := s.store.DeleteAllTokensForUser(r.Context(), id); err != nil {
		s.log.Error("revoke tokens after reset", "err", err)
	}
	if err := s.logAuditEnv(r, ActionAuthChangePassword, "", "", user.Email, `{"via":"portal","by":"admin"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/users/"+id+"/edit", "success", "Password reset and tokens revoked.")
}

// ── Admin: SCIM tokens ────────────────────────────────────────────────────────

func (s *Server) handlePortalAdminSCIMTokens(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	tokens, _ := s.store.ListSCIMTokens(r.Context())
	s.portalTmpl.render(w, "portal_admin_scim_tokens.html", struct {
		portalBase
		Tokens                   []*model.SCIMToken
		Success, Error, NewToken string
	}{newPortalBase(pc, "admin-scim-tokens"), tokens,
		r.URL.Query().Get("success"), r.URL.Query().Get("error"), r.URL.Query().Get("token")})
}

func (s *Server) handlePortalAdminSCIMTokenNew(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	desc := strings.TrimSpace(r.FormValue("description"))
	if desc == "" {
		flashRedirect(w, r, "/portal/admin/scim-tokens", "error", "Description is required.")
		return
	}
	rawToken, err := auth.GenerateRawToken()
	if err != nil {
		s.log.Error("generate scim token", "err", err)
		flashRedirect(w, r, "/portal/admin/scim-tokens", "error", "Token issue failed.")
		return
	}
	t := &model.SCIMToken{
		ID:          uuid.NewString(),
		TokenHash:   auth.HashToken(rawToken),
		Description: desc,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateSCIMToken(r.Context(), t); err != nil {
		s.log.Error("create scim token", "err", err)
		flashRedirect(w, r, "/portal/admin/scim-tokens", "error", "Token issue failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionSCIMTokenCreate, "", "", desc, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/scim-tokens", "token", rawToken)
}

func (s *Server) handlePortalAdminSCIMTokenDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteSCIMToken(r.Context(), id); err != nil {
		flashRedirect(w, r, "/portal/admin/scim-tokens", "error", "Delete failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionSCIMTokenDelete, "", "", id, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/scim-tokens", "success", "Token deleted.")
}

// ── Admin: SCIM group → role mappings ─────────────────────────────────────────

type scimGroupRoleView struct {
	ID, GroupID, DisplayName string
	ProjectName, EnvName     string
	Role                     string
}

func (s *Server) handlePortalAdminSCIMGroupRoles(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	rows, err := s.store.ListSCIMGroupRoles(r.Context())
	if err != nil {
		http.Error(w, "list mappings failed", http.StatusInternalServerError)
		return
	}
	projectByID := map[string]*model.Project{}
	envSlugByID := map[string]string{}
	for _, gr := range rows {
		if gr.ProjectID == nil {
			continue
		}
		pid := *gr.ProjectID
		if _, ok := projectByID[pid]; ok {
			continue
		}
		p, err := s.store.GetProjectByID(r.Context(), pid)
		if err != nil {
			projectByID[pid] = nil
			continue
		}
		projectByID[pid] = p
		envs, _ := s.store.ListEnvironments(r.Context(), pid)
		for _, e := range envs {
			envSlugByID[e.ID] = e.Slug
		}
	}
	views := make([]scimGroupRoleView, 0, len(rows))
	for _, gr := range rows {
		v := scimGroupRoleView{
			ID: gr.ID, GroupID: gr.GroupID, DisplayName: gr.DisplayName, Role: gr.Role,
		}
		if gr.ProjectID != nil {
			if p := projectByID[*gr.ProjectID]; p != nil {
				v.ProjectName = p.Name + " (" + p.Slug + ")"
			} else {
				v.ProjectName = "(missing)"
			}
		}
		if gr.EnvID != nil {
			v.EnvName = envSlugByID[*gr.EnvID]
		}
		views = append(views, v)
	}
	s.portalTmpl.render(w, "portal_admin_scim_group_roles.html", struct {
		portalBase
		Mappings       []scimGroupRoleView
		Success, Error string
	}{newPortalBase(pc, "admin-scim-group-roles"), views,
		r.URL.Query().Get("success"), r.URL.Query().Get("error")})
}

type scimGroupRoleForm struct {
	DisplayName, GroupID, ProjectSlug, EnvSlug, Role string
}

func (s *Server) handlePortalAdminSCIMGroupRoleNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	projects, _ := s.store.ListProjects(r.Context())

	render := func(form scimGroupRoleForm, errMsg string) {
		s.portalTmpl.render(w, "portal_admin_scim_group_role_new.html", struct {
			portalBase
			Form     scimGroupRoleForm
			Projects []*model.Project
			Error    string
		}{newPortalBase(pc, "admin-scim-group-roles"), form, projects, errMsg})
	}

	if r.Method == http.MethodGet {
		render(scimGroupRoleForm{Role: model.RoleViewer}, "")
		return
	}
	_ = r.ParseForm()
	form := scimGroupRoleForm{
		DisplayName: strings.TrimSpace(r.FormValue("display_name")),
		GroupID:     strings.TrimSpace(r.FormValue("group_id")),
		ProjectSlug: strings.TrimSpace(r.FormValue("project_slug")),
		EnvSlug:     strings.TrimSpace(r.FormValue("env_slug")),
		Role:        r.FormValue("role"),
	}
	if form.GroupID == "" || form.ProjectSlug == "" {
		render(form, "Group ID and project are required.")
		return
	}
	if !isValidGroupRole(form.Role) {
		render(form, "Role must be viewer, editor, or owner.")
		return
	}
	p, err := s.store.GetProject(r.Context(), form.ProjectSlug)
	if errors.Is(err, store.ErrNotFound) {
		render(form, "Project not found.")
		return
	}
	if err != nil {
		s.log.Error("get project", "err", err)
		render(form, "Lookup failed.")
		return
	}
	var envID *string
	if form.EnvSlug != "" {
		env, err := s.store.GetEnvironment(r.Context(), p.ID, form.EnvSlug)
		if errors.Is(err, store.ErrNotFound) {
			render(form, "Environment not found in this project.")
			return
		}
		if err != nil {
			render(form, "Lookup failed.")
			return
		}
		envID = &env.ID
	}
	displayName := form.DisplayName
	if displayName == "" {
		displayName = form.GroupID
	}
	gr, err := s.store.SetSCIMGroupRole(r.Context(), form.GroupID, displayName, &p.ID, envID, form.Role)
	if err != nil {
		s.log.Error("set scim group role", "err", err)
		render(form, "Save failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionSCIMGroupSync, p.ID, "", gr.ID, `{"via":"portal","kind":"mapping"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/scim-group-roles", "success", "Mapping created.")
}

func (s *Server) handlePortalAdminSCIMGroupRoleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteSCIMGroupRole(r.Context(), id); err != nil {
		flashRedirect(w, r, "/portal/admin/scim-group-roles", "error", "Delete failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionSCIMGroupSync, "", "", id, `{"via":"portal","kind":"mapping_delete"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/scim-group-roles", "success", "Mapping deleted.")
}

// ── Admin: Projects (envs + members) ──────────────────────────────────────────

// handlePortalAdminProjectNew renders the new-project form on GET and creates
// the project on POST. Server admins can create projects regardless of project
// membership; the creating admin is auto-added as the project owner so they
// retain access via project-level checks.
func (s *Server) handlePortalAdminProjectNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	render := func(name, slug, errMsg string) {
		s.portalTmpl.render(w, "portal_admin_project_new.html", struct {
			portalBase
			Name, Slug, Error string
		}{newPortalBase(pc, "admin-projects"), name, slug, errMsg})
	}
	if r.Method == http.MethodGet {
		render("", "", "")
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	slug := strings.ToLower(strings.TrimSpace(r.FormValue("slug")))
	if slug == "" {
		slug = toSlug(name)
	}
	if name == "" {
		render(name, slug, "Name is required.")
		return
	}
	if !slugRe.MatchString(slug) {
		render(name, slug, "Slug must be lowercase alphanumeric with hyphens (2–63 chars).")
		return
	}
	p, err := s.store.CreateProject(r.Context(), name, slug)
	if errors.Is(err, store.ErrConflict) {
		render(name, slug, "A project with that name or slug already exists.")
		return
	}
	if err != nil {
		s.log.Error("portal admin create project", "err", err)
		render(name, slug, "Create failed.")
		return
	}
	// Generate and store a PEK; non-fatal if KMS is briefly unavailable
	// (matches the JSON handler's behaviour).
	pek := make([]byte, 32)
	if _, randErr := rand.Read(pek); randErr == nil {
		if encPEK, wrapErr := s.kp.WrapDEK(r.Context(), pek); wrapErr == nil {
			if err := s.store.SetProjectKey(r.Context(), p.ID, encPEK, time.Now().UTC()); err != nil {
				s.log.Warn("portal admin set project key", "project", p.ID, "err", err)
			}
		} else {
			s.log.Warn("portal admin wrap project key", "project", p.ID, "err", wrapErr)
		}
	}
	// Auto-add the creating admin as owner.
	if pc.User != nil {
		if err := s.store.AddProjectMember(r.Context(), p.ID, pc.User.ID, model.RoleOwner, nil); err != nil {
			s.log.Error("portal admin add project owner", "err", err)
		}
	}
	if err := s.logAudit(r, ActionProjectCreate, p.ID, p.Slug); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/projects/"+p.Slug, "success", "Project created.")
}

func (s *Server) handlePortalAdminProjectDelete(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	p, err := s.store.GetProject(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		flashRedirect(w, r, "/portal/admin/projects", "error", "Project not found.")
		return
	}
	if err != nil {
		s.log.Error("portal admin delete project lookup", "err", err)
		flashRedirect(w, r, "/portal/admin/projects", "error", "Lookup failed.")
		return
	}
	if err := s.store.DeleteProject(r.Context(), slug); err != nil {
		s.log.Error("portal admin delete project", "err", err)
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Delete failed.")
		return
	}
	if err := s.logAudit(r, ActionProjectDelete, p.ID, slug); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/projects", "success", "Project deleted.")
}

func (s *Server) handlePortalAdminProjectRotateKey(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	p, err := s.store.GetProject(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		flashRedirect(w, r, "/portal/admin/projects", "error", "Project not found.")
		return
	}
	if err != nil {
		s.log.Error("portal admin rotate key lookup", "err", err)
		flashRedirect(w, r, "/portal/admin/projects", "error", "Lookup failed.")
		return
	}
	if err := s.rotateProjectPEK(r.Context(), p); err != nil {
		if errors.Is(err, errProjectMissingPEK) {
			flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Project has no envelope key. Run vaultd migrate-keys first.")
			return
		}
		s.log.Error("portal admin rotate key", "project", slug, "err", err)
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Rotate failed.")
		return
	}
	if err := s.logAudit(r, ActionProjectRotateKey, p.ID, slug); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/projects/"+slug, "success", "Project key rotated. All secrets re-encrypted.")
}

func (s *Server) handlePortalAdminProjects(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	projects, err := s.store.ListProjects(r.Context())
	if err != nil {
		http.Error(w, "list projects failed", http.StatusInternalServerError)
		return
	}
	s.portalTmpl.render(w, "portal_admin_projects.html", struct {
		portalBase
		Projects       []*model.Project
		Success, Error string
	}{newPortalBase(pc, "admin-projects"), projects,
		r.URL.Query().Get("success"), r.URL.Query().Get("error")})
}

type projectMemberView struct {
	UserID, Email, Role, EnvSlug string
}

func (s *Server) handlePortalAdminProjectEdit(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	slug := r.PathValue("project")
	p, err := s.store.GetProject(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	envs, _ := s.store.ListEnvironments(r.Context(), p.ID)
	members, _ := s.store.ListProjectMembers(r.Context(), p.ID)
	users, _ := s.store.ListUsers(r.Context())

	envSlugByID := map[string]string{}
	for _, e := range envs {
		envSlugByID[e.ID] = e.Slug
	}
	emailByUserID := make(map[string]string, len(users))
	for _, u := range users {
		emailByUserID[u.ID] = u.Email
	}
	memberViews := make([]projectMemberView, 0, len(members))
	for _, m := range members {
		v := projectMemberView{UserID: m.UserID, Role: m.Role, Email: emailByUserID[m.UserID]}
		if m.EnvID != nil {
			v.EnvSlug = envSlugByID[*m.EnvID]
		}
		memberViews = append(memberViews, v)
	}
	s.portalTmpl.render(w, "portal_admin_project_edit.html", struct {
		portalBase
		Project        *model.Project
		Envs           []*model.Environment
		Members        []projectMemberView
		Success, Error string
	}{newPortalBase(pc, "admin-projects"), p, envs, memberViews,
		r.URL.Query().Get("success"), r.URL.Query().Get("error")})
}

func (s *Server) handlePortalAdminProjectEnvNew(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	p, err := s.store.GetProject(r.Context(), slug)
	if err != nil {
		flashRedirect(w, r, "/portal/admin/projects", "error", "Project not found.")
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Environment name is required.")
		return
	}
	envSlug := toSlug(name)
	env, err := s.store.CreateEnvironment(r.Context(), p.ID, name, envSlug)
	if errors.Is(err, store.ErrConflict) {
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Environment already exists.")
		return
	}
	if err != nil {
		s.log.Error("create env", "err", err)
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Create failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionEnvCreate, p.ID, env.ID, env.Slug, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/projects/"+slug, "success", "Environment created.")
}

func (s *Server) handlePortalAdminProjectEnvDelete(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	envSlug := r.PathValue("env")
	p, err := s.store.GetProject(r.Context(), slug)
	if err != nil {
		flashRedirect(w, r, "/portal/admin/projects", "error", "Project not found.")
		return
	}
	if err := s.store.DeleteEnvironment(r.Context(), p.ID, envSlug); err != nil {
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Delete failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionEnvDelete, p.ID, "", envSlug, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/projects/"+slug, "success", "Environment deleted.")
}

func (s *Server) handlePortalAdminProjectMemberNew(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	p, err := s.store.GetProject(r.Context(), slug)
	if err != nil {
		flashRedirect(w, r, "/portal/admin/projects", "error", "Project not found.")
		return
	}
	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	role := r.FormValue("role")
	envSlug := strings.TrimSpace(r.FormValue("env_slug"))

	if email == "" || !validRole(role) {
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Email and a valid role are required.")
		return
	}
	user, err := s.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "User not found.")
		return
	}
	if err != nil {
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Lookup failed.")
		return
	}
	var envID *string
	auditEnv := ""
	if envSlug != "" {
		env, err := s.store.GetEnvironment(r.Context(), p.ID, envSlug)
		if errors.Is(err, store.ErrNotFound) {
			flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Env not found.")
			return
		}
		if err != nil {
			flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Lookup failed.")
			return
		}
		envID = &env.ID
		auditEnv = env.ID
	}
	if err := s.store.AddProjectMember(r.Context(), p.ID, user.ID, role, envID); err != nil {
		s.log.Error("add member", "err", err)
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Add failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionMemberAdd, p.ID, auditEnv, user.Email, `{"via":"portal","role":"`+role+`"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/projects/"+slug, "success", "Member added.")
}

func (s *Server) handlePortalAdminProjectMemberDelete(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	userID := r.PathValue("user_id")
	p, err := s.store.GetProject(r.Context(), slug)
	if err != nil {
		flashRedirect(w, r, "/portal/admin/projects", "error", "Project not found.")
		return
	}
	_ = r.ParseForm()
	envSlug := strings.TrimSpace(r.FormValue("env_slug"))
	var envID *string
	auditEnv := ""
	if envSlug != "" {
		env, err := s.store.GetEnvironment(r.Context(), p.ID, envSlug)
		if err == nil {
			envID = &env.ID
			auditEnv = env.ID
		}
	}
	if err := s.store.RemoveProjectMember(r.Context(), p.ID, userID, envID); err != nil {
		flashRedirect(w, r, "/portal/admin/projects/"+slug, "error", "Remove failed.")
		return
	}
	if err := s.logAuditEnv(r, ActionMemberRemove, p.ID, auditEnv, userID, `{"via":"portal"}`); err != nil {
		http.Error(w, "audit unavailable", http.StatusInternalServerError)
		return
	}
	flashRedirect(w, r, "/portal/admin/projects/"+slug, "success", "Member removed.")
}
