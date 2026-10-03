// Package docker is an open-source stub for the Docker-backed ExecutorProvider.
//
// This is a placeholder: the Docker executor lands with its feature milestone.
// Until then the stub keeps the executor_factory and job_pool imports compiling
// while the "docker" runner executor type stays unavailable.
//
// The only entry point is NewProvider; it always fails so JobPool refuses to start
// and the operator sees a clear message in the logs.
package docker

import (
	"errors"

	"github.com/semaphoreui/semaphore/services/tasks"
	"github.com/semaphoreui/semaphore/util"
)

func NewProvider(_ util.RunnerDockerConfig) (tasks.ExecutorProvider, error) {
	return nil, errors.New("docker executor is only available in the proprietary build")
}
