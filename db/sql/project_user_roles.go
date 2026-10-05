package sql

import (
	"github.com/go-gorp/gorp/v3"
	"github.com/semaphoreui/semaphore/db"
)

// Fork feature: IdP-managed project memberships (provenance rows for the
// OIDC role mapping — see api/login_oidc_roles.go). Kept out of the
// upstream store files to minimize re-sync churn.

// GetExternalProjectUsers returns the user's IdP-managed memberships.
func (d *SqlDb) GetExternalProjectUsers(userID int) (projectUsers []db.ProjectUser, err error) {
	_, err = d.selectAll(&projectUsers,
		"select * from project__user where user_id=? and external=1",
		userID)
	return
}

// UpsertExternalProjectUser inserts or updates an IdP-managed membership.
// project__user has a unique (project_id, user_id) constraint.
func (d *SqlDb) UpsertExternalProjectUser(projectUser db.ProjectUser) error {
	query := "insert into project__user (project_id, user_id, `role`, external) values (?, ?, ?, 1) " +
		"on conflict (`project_id`, `user_id`) do update set `role`=excluded.`role`"

	if _, isMySQL := d.Sql().Dialect.(gorp.MySQLDialect); isMySQL {
		query = "insert into project__user (project_id, user_id, `role`, external) values (?, ?, ?, 1) " +
			"on duplicate key update `role`=values(`role`)"
	}

	_, err := d.exec(query,
		projectUser.ProjectID,
		projectUser.UserID,
		projectUser.Role)

	return err
}

// DeleteExternalProjectUser removes an IdP-managed membership.
func (d *SqlDb) DeleteExternalProjectUser(projectID, userID int) error {
	_, err := d.exec(
		"delete from project__user where user_id=? and project_id=? and external=1",
		userID,
		projectID)
	return err
}
