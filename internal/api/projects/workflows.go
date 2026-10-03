package projects

import (
	"net/http"

	"github.com/semaphoreui/semaphore/api/helpers"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/internal/interfaces"
)

// workflowController is a placeholder: workflows are not implemented yet and
// land with their feature milestone. The stub keeps the build compiling and
// the API surface present (returning empty collections / 404) until then.
// Feature availability is decided by internal/pkg/features.
type workflowController struct{}

func NewWorkflowController(svc interfaces.WorkflowService, workflowRepo db.WorkflowManager) interfaces.WorkflowController {
	return &workflowController{}
}

func (c *workflowController) GetWorkflows(w http.ResponseWriter, r *http.Request) {
	helpers.WriteJSON(w, http.StatusOK, []struct{}{})
}

func (c *workflowController) AddWorkflow(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (c *workflowController) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (c *workflowController) UpdateWorkflow(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (c *workflowController) RemoveWorkflow(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (c *workflowController) RunWorkflow(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (c *workflowController) StopWorkflowRun(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (c *workflowController) GetWorkflowRuns(w http.ResponseWriter, r *http.Request) {
	helpers.WriteJSON(w, http.StatusOK, []struct{}{})
}

func (c *workflowController) GetWorkflowRun(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (c *workflowController) GetWorkflowRunArtifacts(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func (c *workflowController) GetWorkflowApprovals(w http.ResponseWriter, r *http.Request) {
	helpers.WriteJSON(w, http.StatusOK, []struct{}{})
}

func (c *workflowController) ResolveWorkflowApproval(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}
