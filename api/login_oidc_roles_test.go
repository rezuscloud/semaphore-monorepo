package api

import (
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	"github.com/semaphoreui/semaphore/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit tests for the fork's OIDC role-mapping engine (api/login_oidc_roles.go).
// End-to-end coverage (claim plumbing through the login flow) lives in
// login_oidc_test.go; the live Authentik proof in
// login_authentik_integration_test.go.

func rolesTestStore(t *testing.T) *sql.SqlDb {
	t.Helper()
	store := sql.CreateTestStore()
	t.Cleanup(func() { _ = store.Close })
	return store
}

func rolesTestUser(t *testing.T, store db.Store, username string) db.User {
	t.Helper()
	user, err := store.CreateUserWithoutPassword(db.User{
		Username: username,
		Name:     username,
		Email:    username + "@rezus.cloud",
		External: true,
	})
	require.NoError(t, err)
	return user
}

func rolesTestProject(t *testing.T, store db.Store, name string) db.Project {
	t.Helper()
	project, err := store.CreateProject(db.Project{Name: name})
	require.NoError(t, err)
	return project
}

func mappingProvider(groupsClaim string, cfg *util.RoleMappingConfig) util.GroupsClaimProvider {
	p := &util.OidcProvider{
		GroupsClaim: groupsClaim,
		RoleMapping: cfg,
	}
	return p
}

func TestExtractGroups(t *testing.T) {
	claims := map[string]any{
		"groups_str":    []string{"b", "a"},
		"groups_any":    []any{"x", "y", 42},
		"groups_scalar": "lonely",
		"groups_empty":  []any{},
		"groups_num":    7,
	}

	assert.Equal(t, []string{"a", "b"}, extractGroups(claims, "groups_str"))
	assert.Equal(t, []string{"x", "y"}, extractGroups(claims, "groups_any"))
	assert.Equal(t, []string{"lonely"}, extractGroups(claims, "groups_scalar"))
	assert.Nil(t, extractGroups(claims, "groups_empty"))
	assert.Nil(t, extractGroups(claims, "groups_absent"))
	assert.Nil(t, extractGroups(claims, "groups_num"))
	assert.Nil(t, extractGroups(claims, ""))
}

func TestApplyRoleMappingInertWhenUnconfigured(t *testing.T) {
	store := rolesTestStore(t)
	project := rolesTestProject(t, store, "infra")
	user := rolesTestUser(t, store, "idpuser")

	// no groups claim, no mapping: nothing may happen
	require.NoError(t, applyRoleMapping(store, user, []string{"admins"}, mappingProvider("", nil)))

	fresh, err := store.GetUser(user.ID)
	require.NoError(t, err)
	assert.False(t, fresh.Admin)

	// groups claim set but empty mapping config: still inert
	require.NoError(t, applyRoleMapping(store, user, []string{"admins"},
		mappingProvider("groups", &util.RoleMappingConfig{})))

	_, err = store.GetProjectUser(project.ID, user.ID)
	assert.ErrorIs(t, err, db.ErrNotFound)
}

func TestApplyRoleMappingAdminPromoteAndDemote(t *testing.T) {
	store := rolesTestStore(t)
	user := rolesTestUser(t, store, "idpuser")
	provider := mappingProvider("groups", &util.RoleMappingConfig{Admin: []string{"semaphore-admins"}})

	require.NoError(t, applyRoleMapping(store, user, []string{"others", "semaphore-admins"}, provider))

	promoted, err := store.GetUser(user.ID)
	require.NoError(t, err)
	assert.True(t, promoted.Admin, "group membership must promote")

	// re-login without the group: demote (IdP authoritative)
	require.NoError(t, applyRoleMapping(store, promoted, []string{"others"}, provider))

	demoted, err := store.GetUser(user.ID)
	require.NoError(t, err)
	assert.False(t, demoted.Admin, "group loss must demote")
}

func TestApplyRoleMappingAdminUntouchedWhenListNil(t *testing.T) {
	store := rolesTestStore(t)
	user := rolesTestUser(t, store, "idpuser")

	// local admin, mapping has no admin list: flag must stay untouched
	user.Admin = true
	err := store.UpdateUser(db.UserWithPwd{User: user, Pwd: "x1234567890"})
	require.NoError(t, err)

	require.NoError(t, applyRoleMapping(store, user, []string{"semaphore-admins"}, mappingProvider("groups", &util.RoleMappingConfig{})))

	fresh, err := store.GetUser(user.ID)
	require.NoError(t, err)
	assert.True(t, fresh.Admin, "admin flag must be untouched when the admin list is nil")
}

func TestApplyRoleMappingProjectGrantChangeAndRevoke(t *testing.T) {
	store := rolesTestStore(t)
	project := rolesTestProject(t, store, "infra")
	user := rolesTestUser(t, store, "idpuser")
	provider := mappingProvider("groups", &util.RoleMappingConfig{
		ProjectRoles: []util.RoleMappingRule{
			{Project: "infra", Role: string(db.ProjectGuest), Groups: []string{"viewers"}},
		},
	})

	// grant
	require.NoError(t, applyRoleMapping(store, user, []string{"viewers"}, provider))

	pu, err := store.GetProjectUser(project.ID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, db.ProjectGuest, pu.Role)
	assert.True(t, pu.External, "mapper-created membership must be flagged external")

	// role change (stronger group now matches)
	provider = mappingProvider("groups", &util.RoleMappingConfig{
		ProjectRoles: []util.RoleMappingRule{
			{Project: "infra", Role: string(db.ProjectOwner), Groups: []string{"owners"}},
		},
	})
	require.NoError(t, applyRoleMapping(store, user, []string{"owners"}, provider))

	pu, err = store.GetProjectUser(project.ID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, db.ProjectOwner, pu.Role)
	assert.True(t, pu.External)

	// revoke: no group matches anymore
	require.NoError(t, applyRoleMapping(store, user, []string{"unrelated"}, provider))

	_, err = store.GetProjectUser(project.ID, user.ID)
	assert.ErrorIs(t, err, db.ErrNotFound, "stale IdP grant must be revoked")
}

func TestApplyRoleMappingManualMembershipWins(t *testing.T) {
	store := rolesTestStore(t)
	project := rolesTestProject(t, store, "infra")
	user := rolesTestUser(t, store, "idpuser")

	// manual membership: higher than what the mapping would grant
	_, err := store.CreateProjectUser(db.ProjectUser{
		ProjectID: project.ID,
		UserID:    user.ID,
		Role:      db.ProjectOwner,
	})
	require.NoError(t, err)

	provider := mappingProvider("groups", &util.RoleMappingConfig{
		ProjectRoles: []util.RoleMappingRule{
			{Project: "infra", Role: string(db.ProjectGuest), Groups: []string{"viewers"}},
		},
	})

	// with matching group: manual row must not be downgraded
	require.NoError(t, applyRoleMapping(store, user, []string{"viewers"}, provider))
	pu, err := store.GetProjectUser(project.ID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, db.ProjectOwner, pu.Role)
	assert.False(t, pu.External)

	// without matching group: manual row must not be revoked
	require.NoError(t, applyRoleMapping(store, user, nil, provider))
	_, err = store.GetProjectUser(project.ID, user.ID)
	require.NoError(t, err)
}

func TestApplyRoleMappingPrecedence(t *testing.T) {
	store := rolesTestStore(t)
	project := rolesTestProject(t, store, "infra")
	user := rolesTestUser(t, store, "idpuser")

	// custom role weaker than owner; user matches rules for both
	_, err := store.CreateRole(db.Role{
		Slug:        "deployer",
		Name:        "Deployer",
		Permissions: db.CanRunProjectTasks,
	})
	require.NoError(t, err)

	provider := mappingProvider("groups", &util.RoleMappingConfig{
		ProjectRoles: []util.RoleMappingRule{
			{Project: "infra", Role: "deployer", Groups: []string{"deployers"}},
			{Project: "infra", Role: string(db.ProjectGuest), Groups: []string{"everyone"}},
			{Project: "infra", Role: string(db.ProjectOwner), Groups: []string{"admins"}},
		},
	})

	require.NoError(t, applyRoleMapping(store, user, []string{"everyone", "deployers", "admins"}, provider))

	pu, err := store.GetProjectUser(project.ID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, db.ProjectOwner, pu.Role, "strongest matching grant must win")

	// drop the strongest group: custom deployer beats built-in guest
	require.NoError(t, applyRoleMapping(store, user, []string{"everyone", "deployers"}, provider))
	pu, err = store.GetProjectUser(project.ID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, db.ProjectUserRole("deployer"), pu.Role)
}

func TestApplyRoleMappingUnknownProjectAndRoleSkipped(t *testing.T) {
	store := rolesTestStore(t)
	user := rolesTestUser(t, store, "idpuser")

	provider := mappingProvider("groups", &util.RoleMappingConfig{
		ProjectRoles: []util.RoleMappingRule{
			{Project: "does-not-exist", Role: string(db.ProjectGuest), Groups: []string{"viewers"}},
			{Project: "does-not-exist-either", Role: "no-such-role", Groups: []string{"viewers"}},
		},
	})

	require.NoError(t, applyRoleMapping(store, user, []string{"viewers"}, provider))

	managed, err := store.GetExternalProjectUsers(user.ID)
	require.NoError(t, err)
	assert.Empty(t, managed)
}

func TestApplyRoleMappingWritesAuditEvents(t *testing.T) {
	store := rolesTestStore(t)
	rolesTestProject(t, store, "infra") // referenced by name in the rules
	user := rolesTestUser(t, store, "idpuser")
	provider := mappingProvider("groups", &util.RoleMappingConfig{
		Admin: []string{"semaphore-admins"},
		ProjectRoles: []util.RoleMappingRule{
			{Project: "infra", Role: string(db.ProjectGuest), Groups: []string{"viewers"}},
		},
	})

	require.NoError(t, applyRoleMapping(store, user, []string{"semaphore-admins", "viewers"}, provider))

	// next login: the handler always passes the fresh store row
	fresh, err := store.GetUser(user.ID)
	require.NoError(t, err)
	require.NoError(t, applyRoleMapping(store, fresh, nil, provider))

	events, err := store.GetUserEvents(user.ID, db.RetrieveQueryParams{})
	require.NoError(t, err)

	var descriptions []string
	for _, e := range events {
		if e.ObjectType != nil && *e.ObjectType == db.EventUser {
			descriptions = append(descriptions, *e.Description)
		}
	}

	assert.Contains(t, descriptionsString(descriptions), "admin set to true")
	assert.Contains(t, descriptionsString(descriptions), "granted guest in project 'infra'")
	assert.Contains(t, descriptionsString(descriptions), "admin set to false")
	assert.Contains(t, descriptionsString(descriptions), "revoked guest in project")
}

func descriptionsString(descriptions []string) string {
	out := ""
	for _, d := range descriptions {
		out += d + "\n"
	}
	return out
}
