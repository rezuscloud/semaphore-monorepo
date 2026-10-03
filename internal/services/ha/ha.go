package ha

import (
	"github.com/semaphoreui/semaphore/api/sockets"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/internal/interfaces"
	"github.com/semaphoreui/semaphore/services/schedules"
)

// NodeRegistry manages node heartbeats and cluster membership tracking
// in HA mode. In active-active setups every Semaphore instance registers
// itself and periodically refreshes a heartbeat so other nodes can detect
// liveness.
type NodeRegistry interface {
	Start() error
	Stop()
	NodeCount() int
	NodeID() string
}

// OrphanCleaner periodically detects tasks whose owning node has died and
// marks them as failed so they do not remain stuck in "running" forever.
type OrphanCleaner interface {
	Start()
	Stop()
}

// ClusterInspector is the read surface for the Cluster Dashboard. It exposes
// cluster membership and Redis keyspace stats. The Redis-backed implementation
// is implemented with the HA feature milestone; the placeholder returns nil.
type ClusterInspector interface {
	// Nodes returns current cluster membership with heartbeat info.
	Nodes() ([]interfaces.NodeInfo, error)
	// RedisInfo returns Redis server / keyspace stats and a key-group breakdown.
	RedisInfo() (interfaces.RedisInfo, error)
}

// Placeholders — replaced by the real implementations with the HA feature milestone.

func NewNodeRegistry() NodeRegistry                           { return nil }
func NewScheduleDeduplicator() schedules.ScheduleDeduplicator { return nil }
func NewWSBroadcaster() sockets.Broadcaster                   { return nil }
func NewOrphanCleaner(_ db.Store) OrphanCleaner               { return nil }
func NewClusterInspector() ClusterInspector                   { return nil }
func NewWorkflowRunLocker() interfaces.WorkflowRunLocker  { return nil }
