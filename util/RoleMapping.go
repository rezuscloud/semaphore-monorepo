package util

// RoleMappingConfig maps identity-provider group claims to Semaphore
// privileges, applied at every OIDC login (fork feature — see the repo
// wiki "SSO-OIDC" page).
//
// Semantics:
//
//   - "admin" lists groups granting the global admin flag. When the list
//     is present (non-nil), the provider is authoritative for the flag —
//     logins promote and demote. When nil, the flag is untouched.
//   - "project_roles" maps groups to project membership roles. Rules
//     reference projects by name and roles by slug — built-in
//     (owner/manager/task_runner/guest) or custom (role table). When
//     several rules for one project match the user's groups, the grant
//     with the strongest permission set wins; ties prefer built-in
//     roles, then earlier rules.
//   - Memberships created by the mapper are flagged and reconciled at
//     every login; manual memberships are never modified or revoked.
type RoleMappingConfig struct {
	Admin        []string          `json:"admin"`
	ProjectRoles []RoleMappingRule `json:"project_roles"`
}

// RoleMappingRule grants a project membership role to users holding any
// of the listed groups.
type RoleMappingRule struct {
	Project string   `json:"project"`
	Role    string   `json:"role"`
	Groups  []string `json:"groups"`
}

// GroupsClaimProvider is implemented by OidcProvider when a groups claim
// is configured. Absent when the role mapping feature is off.
type GroupsClaimProvider interface {
	GetGroupsClaim() string
	GetRoleMapping() *RoleMappingConfig
}

func (p *OidcProvider) GetGroupsClaim() string {
	return p.GroupsClaim
}

func (p *OidcProvider) GetRoleMapping() *RoleMappingConfig {
	return p.RoleMapping
}
