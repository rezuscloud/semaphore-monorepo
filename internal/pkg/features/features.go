package features

import (
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/internal/interfaces"
)

func GetFeatures(user *db.User, plan string) interfaces.Features {
	return interfaces.Features{}
}
