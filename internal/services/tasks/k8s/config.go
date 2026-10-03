// Package k8s is an open-source stub for the Kubernetes-backed ExecutorProvider.
//
// This is a placeholder: the Kubernetes executor lands with its feature milestone.
// Until then the stub keeps the executor_factory and job_pool imports compiling
// while the "k8s" runner executor type stays unavailable. The real provider runs
// each task in an ephemeral Pod.
// imports compiling while making it explicit that the "k8s" runner executor type
// requires the proprietary build.
//
// The only entry point is NewProvider; it always fails so JobPool refuses to start
// and the operator sees a clear message in the logs.
package k8s

import (
	"errors"

	"github.com/semaphoreui/semaphore/services/tasks"
	"github.com/semaphoreui/semaphore/util"
)

func NewProvider(_ util.RunnerK8sConfig) (tasks.ExecutorProvider, error) {
	return nil, errors.New("k8s executor is only available in the proprietary build")
}
