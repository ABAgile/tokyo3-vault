package mockstore

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-vault/internal/model"
)

// TestStub_AllMethods calls every method on a Stub to get coverage.
func TestStub_AllMethods(t *testing.T) {
	s := Stub{}
	ctx := context.Background()

	// Users
	s.CreateUser(ctx, "", "", "")
	s.CreateOIDCUser(ctx, "", "", "", "")
	s.GetUserByEmail(ctx, "")
	s.GetUserByID(ctx, "")
	s.GetUserByOIDCSubject(ctx, "", "")
	s.ListUsers(ctx)
	s.HasAdminUser(ctx)
	s.UpdateUserPassword(ctx, "", "")
	s.SetUserOIDCIdentity(ctx, "", "", "")
	s.SetUserActive(ctx, "", false)
	s.DeleteAllTokensForUser(ctx, "")

	// Tokens
	s.CreateToken(ctx, &model.Token{})
	s.GetTokenByHash(ctx, "")
	s.ListTokens(ctx, "")
	s.ListTokensWithAccess(ctx, "", "")
	s.DeleteToken(ctx, "", "")

	// Projects
	s.CreateProject(ctx, "", "")
	s.GetProject(ctx, "")
	s.GetProjectByID(ctx, "")
	s.ListProjects(ctx)
	s.ListProjectsByMember(ctx, "")
	s.DeleteProject(ctx, "")
	s.SetProjectKey(ctx, "", nil, time.Now())
	s.RewrapProjectDEKs(ctx, "", func(b []byte) ([]byte, error) { return b, nil })
	s.RotateProjectPEK(ctx, "", nil, time.Now(), func(b []byte) ([]byte, error) { return b, nil })
	s.ListProjectsForPEKRotation(ctx, time.Now())

	// Project members
	s.AddProjectMember(ctx, "", "", "", nil)
	s.GetProjectMember(ctx, "", "")
	s.GetProjectMemberForEnv(ctx, "", "", "")
	s.ListProjectMembers(ctx, "")
	s.ListProjectMembersWithAccess(ctx, "", "")
	s.UpdateProjectMember(ctx, "", "", "", nil)
	s.RemoveProjectMember(ctx, "", "", nil)

	// Environments
	s.CreateEnvironment(ctx, "", "", "")
	s.GetEnvironment(ctx, "", "")
	s.ListEnvironments(ctx, "")
	s.DeleteEnvironment(ctx, "", "")

	// Secrets
	s.SetSecret(ctx, "", "", "", nil, nil, nil, nil)
	s.GetSecret(ctx, "", "", "")
	s.ListSecrets(ctx, "", "")
	s.DeleteSecret(ctx, "", "", "")
	s.ListSecretVersions(ctx, "")
	s.GetSecretVersion(ctx, "", "")
	s.RollbackSecret(ctx, "", "")
	s.PruneSecretVersions(ctx, "", "", 0, time.Now())
	s.ListSecretsForPrune(ctx)

	// Dynamic backends
	s.SetDynamicBackend(ctx, "", "", "", "", nil, nil, 0, 0)
	s.GetDynamicBackend(ctx, "", "", "")
	s.GetDynamicBackendByID(ctx, "")
	s.DeleteDynamicBackend(ctx, "", "", "")

	// Dynamic roles
	s.SetDynamicRole(ctx, "", "", "", "", nil)
	s.GetDynamicRole(ctx, "", "")
	s.ListDynamicRoles(ctx, "")
	s.DeleteDynamicRole(ctx, "", "")

	// Dynamic leases
	s.CreateDynamicLease(ctx, "", "", "", "", "", "", "", time.Now(), nil)
	s.GetDynamicLease(ctx, "")
	s.ListDynamicLeases(ctx, "", "")
	s.RevokeDynamicLease(ctx, "")
	s.ListExpiredDynamicLeases(ctx)

	// SCIM tokens
	s.CreateSCIMToken(ctx, &model.SCIMToken{})
	s.GetSCIMTokenByHash(ctx, "")
	s.ListSCIMTokens(ctx)
	s.DeleteSCIMToken(ctx, "")

	// SCIM group roles
	s.SetSCIMGroupRole(ctx, "", "", nil, nil, "")
	s.ListSCIMGroupRoles(ctx)
	s.ListSCIMGroupRolesByGroup(ctx, "")
	s.GetSCIMGroupRole(ctx, "")
	s.DeleteSCIMGroupRole(ctx, "")

	// Cert principals
	s.CreateCertPrincipal(ctx, &model.CertPrincipal{})
	s.GetCertPrincipalBySPIFFEID(ctx, "")
	s.GetCertPrincipalByEmailSAN(ctx, "")
	s.ListCertPrincipals(ctx, "")
	s.ListCertPrincipalsWithAccess(ctx, "", "")
	s.DeleteCertPrincipal(ctx, "", "")
}
