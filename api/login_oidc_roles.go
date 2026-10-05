package api

import (
	"fmt"
	"sort"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/util"
	log "github.com/sirupsen/logrus"
)

// OIDC role mapping (fork feature — see the repo wiki "SSO-OIDC" page).
//
// The engine is identity-provider agnostic: it takes the extracted group
// list and the provider's mapping config, computes the desired
// privileges, and reconciles the user's admin flag and IdP-managed
// project memberships against them. Memberships created here carry
// project__user.external=1 and are the only rows the reconcile touches —
// manual memberships always win.

// extractGroups pulls the configured groups claim out of a verified ID
// token's claims. Accepts a JSON array of strings, an array of arbitrary
// scalars (stringified), or a plain string.
func extractGroups(claims map[string]any, claim string) (groups []string) {
	if claim == "" {
		return nil
	}

	switch v := claims[claim].(type) {
	case []string:
		groups = v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				groups = append(groups, s)
			}
		}
	case string:
		if v != "" {
			groups = []string{v}
		}
	}

	sort.Strings(groups)
	return groups
}

// roleGrant is a resolved desired grant for one project.
type roleGrant struct {
	projectName string
	projectID   int
	role        db.ProjectUserRole
	permissions db.ProjectUserPermission
	builtin     bool
	order       int
}

// desiredGrants resolves the project-role rules against the user's
// groups. Project names are resolved to IDs via the store (missing
// projects are skipped with a warning — the config must survive project
// deletion). Precedence within one project: strongest permission set,
// then built-in over custom slug, then rule order.
func desiredGrants(store db.Store, groups []string, rules []util.RoleMappingRule) (grants []roleGrant, err error) {
	if len(rules) == 0 || len(groups) == 0 {
		return nil, nil
	}

	member := make(map[string]bool, len(groups))
	for _, g := range groups {
		member[g] = true
	}

	projects, err := store.GetAllProjects()
	if err != nil {
		return nil, err
	}

	projectIDs := make(map[string]int, len(projects))
	for _, p := range projects {
		projectIDs[p.Name] = p.ID
	}

	// best grant per project
	type candidate struct {
		grant  roleGrant
		ranked bool
	}
	best := make(map[int]roleGrant)

	for i, rule := range rules {
		projectID, ok := projectIDs[rule.Project]
		if !ok {
			log.Warnf("oidc role mapping: project '%s' not found, rule skipped", rule.Project)
			continue
		}

		matched := false
		for _, g := range rule.Groups {
			if member[g] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		g := roleGrant{
			projectName: rule.Project,
			projectID:   projectID,
			role:        db.ProjectUserRole(rule.Role),
			order:       i,
		}

		if g.role.IsValid() {
			g.builtin = true
			g.permissions = g.role.GetPermissions()
		} else {
			// custom role: resolve from the store (project-scoped or global)
			role, err := store.GetProjectOrGlobalRoleBySlug(projectID, rule.Role)
			if err != nil {
				if err == db.ErrNotFound {
					log.Warnf("oidc role mapping: role '%s' not found for project '%s', rule skipped", rule.Role, rule.Project)
					continue
				}
				return nil, err
			}
			g.permissions = role.Permissions
		}

		cur, ok := best[projectID]
		if !ok || grantStronger(g, cur) {
			best[projectID] = g
		}
	}

	for _, g := range best {
		grants = append(grants, g)
	}

	sort.Slice(grants, func(i, j int) bool { return grants[i].projectName < grants[j].projectName })
	return grants, nil
}

// grantStronger reports whether a should displace b as the grant for a
// project: strongest permissions win; ties prefer built-in; then rule order.
func grantStronger(a, b roleGrant) bool {
	if a.permissions != b.permissions {
		return a.permissions > b.permissions
	}
	if a.builtin != b.builtin {
		return a.builtin
	}
	return a.order < b.order
}

// applyRoleMapping reconciles a user's privileges at login. It is a
// no-op unless the provider configured a groups claim and a mapping.
// Every transition emits an audit event (EventUser) and the reconcile is
// summarized in one log line.
func applyRoleMapping(store db.Store, user db.User, groups []string, provider util.GroupsClaimProvider) error {
	cfg := provider.GetRoleMapping()
	if provider.GetGroupsClaim() == "" || cfg == nil || (cfg.Admin == nil && len(cfg.ProjectRoles) == 0) {
		return nil // feature not configured — fully inert
	}

	log.WithFields(log.Fields{
		"user":   user.Username,
		"groups": groups,
	}).Info("oidc role mapping: login reconcile")

	var events []db.Event

	if cfg.Admin != nil {
		admin := false
		for _, g := range groups {
			for _, ag := range cfg.Admin {
				if g == ag {
					admin = true
					break
				}
			}
			if admin {
				break
			}
		}

		if admin != user.Admin {
			user.Admin = admin
			if err := store.UpdateUser(db.UserWithPwd{User: user}); err != nil {
				return err
			}
			events = append(events, mappingEvent(user, fmt.Sprintf("oidc role mapping: admin set to %v (groups: %v)", admin, groups)))
		}
	}

	grants, err := desiredGrants(store, groups, cfg.ProjectRoles)
	if err != nil {
		return err
	}
	desired := make(map[int]roleGrant, len(grants))
	for _, g := range grants {
		desired[g.projectID] = g
	}

	// reconcile IdP-managed rows: update/create desired, revoke stale
	managed, err := store.GetExternalProjectUsers(user.ID)
	if err != nil {
		return err
	}
	existing := make(map[int]db.ProjectUser, len(managed))
	for _, pu := range managed {
		existing[pu.ProjectID] = pu
	}

	for projectID, grant := range desired {
		pu, has := existing[projectID]
		if has {
			if pu.Role == grant.role {
				continue // already correct
			}
			if err := store.UpsertExternalProjectUser(db.ProjectUser{
				ProjectID: projectID,
				UserID:    user.ID,
				Role:      grant.role,
				External:  true,
			}); err != nil {
				return err
			}
			events = append(events, mappingEvent(user, fmt.Sprintf("oidc role mapping: role in project '%s' changed %s -> %s", grant.projectName, pu.Role, grant.role)))
			continue
		}

		// a manual membership for this project wins — never overwrite
		_, err := store.GetProjectUser(projectID, user.ID)
		switch {
		case err == nil:
			log.WithFields(log.Fields{
				"user":    user.Username,
				"project": grant.projectName,
			}).Info("oidc role mapping: manual membership present, grant skipped")
		case err == db.ErrNotFound:
			if err := store.UpsertExternalProjectUser(db.ProjectUser{
				ProjectID: projectID,
				UserID:    user.ID,
				Role:      grant.role,
				External:  true,
			}); err != nil {
				return err
			}
			events = append(events, mappingEvent(user, fmt.Sprintf("oidc role mapping: granted %s in project '%s' (groups: %v)", grant.role, grant.projectName, groups)))
		default:
			return err
		}
	}

	for projectID, pu := range existing {
		if _, wanted := desired[projectID]; wanted {
			continue
		}
		if err := store.DeleteExternalProjectUser(projectID, user.ID); err != nil {
			return err
		}
		events = append(events, mappingEvent(user, fmt.Sprintf("oidc role mapping: revoked %s in project %d (no matching group)", pu.Role, projectID)))
	}

	for _, e := range events {
		if _, err := store.CreateEvent(e); err != nil {
			log.WithError(err).Warn("oidc role mapping: failed to write audit event")
		}
	}

	return nil
}

func mappingEvent(user db.User, description string) db.Event {
	userID := user.ID
	objectType := db.EventUser
	return db.Event{
		UserID:      &userID,
		ObjectType:  &objectType,
		ObjectID:    &userID,
		Description: &description,
	}
}
