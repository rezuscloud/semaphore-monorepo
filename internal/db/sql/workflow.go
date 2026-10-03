package sql

import (
	"github.com/semaphoreui/semaphore/db"
)

// WorkflowStoreImpl is a no-op placeholder for the workflow store.
// Workflows are not implemented yet and land with their feature milestone;
// the stub keeps the build compiling until then.
type WorkflowStoreImpl struct {
}

func (d *WorkflowStoreImpl) GetWorkflowRunTasks(projectID int, runID int, params db.RetrieveQueryParams) (res []db.TaskWithTpl, err error) {
	return
}

func (d *WorkflowStoreImpl) GetWorkflowTemplates(projectID int, params db.RetrieveQueryParams) (res []db.WorkflowTemplate, err error) {
	return
}

func (d *WorkflowStoreImpl) GetWorkflowTemplate(projectID int, workflowID int) (res db.WorkflowTemplate, err error) {
	return
}

func (d *WorkflowStoreImpl) CreateWorkflowTemplate(workflow db.WorkflowTemplate) (res db.WorkflowTemplate, err error) {
	return
}

func (d *WorkflowStoreImpl) UpdateWorkflowTemplate(workflow db.WorkflowTemplate) (err error) {
	return
}

func (d *WorkflowStoreImpl) DeleteWorkflowTemplate(projectID int, workflowID int) (err error) {
	return
}

func (d *WorkflowStoreImpl) GetWorkflowRuns(projectID int, workflowTemplateID int, params db.RetrieveQueryParams) (res []db.WorkflowRun, err error) {
	return
}

func (d *WorkflowStoreImpl) GetWorkflowRun(projectID int, workflowTemplateID int, runID int) (res db.WorkflowRun, err error) {
	return
}

func (d *WorkflowStoreImpl) GetWorkflowRunByID(projectID int, runID int) (res db.WorkflowRun, err error) {
	return
}

func (d *WorkflowStoreImpl) GetActiveWorkflowRuns() (res []db.WorkflowRun, err error) {
	return
}

func (d *WorkflowStoreImpl) CreateWorkflowRun(run db.WorkflowRun) (res db.WorkflowRun, err error) {
	return
}

func (d *WorkflowStoreImpl) UpdateWorkflowRun(run db.WorkflowRun) (err error) {
	return
}

func (d *WorkflowStoreImpl) UpdateWorkflowRunStatusUnless(run db.WorkflowRun, excluded []db.WorkflowRunStatus) (ok bool, err error) {
	return
}

func (d *WorkflowStoreImpl) SetWorkflowRunRootTask(projectID int, runID int, taskID int) (ok bool, err error) {
	return
}

func (d *WorkflowStoreImpl) GetWorkflowApprovals(projectID int, runID int) (res []db.WorkflowApproval, err error) {
	return
}

func (d *WorkflowStoreImpl) GetWorkflowApproval(projectID int, runID int, nodeID int) (res db.WorkflowApproval, err error) {
	return
}

func (d *WorkflowStoreImpl) CreateWorkflowApproval(approval db.WorkflowApproval) (res db.WorkflowApproval, err error) {
	return
}

func (d *WorkflowStoreImpl) UpdateWorkflowApproval(approval db.WorkflowApproval) (err error) {
	return
}

func (d *WorkflowStoreImpl) ResolveWorkflowApprovalIfPending(approval db.WorkflowApproval) (ok bool, err error) {
	return
}
