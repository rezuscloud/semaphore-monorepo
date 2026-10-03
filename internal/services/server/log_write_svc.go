package server

import (
	"github.com/semaphoreui/semaphore/internal/interfaces"
)

type LogWriteServiceImpl struct {
}

// NewLogWriteService creates a new instance of LogWriteServiceImpl.
func NewLogWriteService() interfaces.LogWriteService {
	return &LogWriteServiceImpl{}
}

func (l *LogWriteServiceImpl) WriteEventLog(event interfaces.EventLogRecord) error {
	return nil
}

func (l *LogWriteServiceImpl) WriteTaskLog(task interfaces.TaskLogRecord) error {
	return nil
}
func (l *LogWriteServiceImpl) WriteResult(task any) error {
	return nil
}
