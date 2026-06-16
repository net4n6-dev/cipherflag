// Package venafi provides the Venafi (Cloud and TPP) certificate export connector.
//
// Ported from cipherflag-EE's Venafi push-scheduler hot-reload work
// (EE CHANGELOG v2.6.0 / ki:0006).
//
// LiveConfig is the mechanism that decouples the push scheduler from the
// handler: the handler calls Set after saving the operator's config update,
// and the always-on Pusher sees the new values on its next cycle — no restart
// required.
package venafi

import (
	"sync"

	"github.com/net4n6-dev/cipherflag/internal/config"
)

// LiveConfig holds a hot-reloadable snapshot of VenafiExportConfig.
// All methods are safe for concurrent use.
type LiveConfig struct {
	mu  sync.RWMutex
	cfg config.VenafiExportConfig
}

// NewLiveConfig creates a LiveConfig initialised with the given config.
func NewLiveConfig(c config.VenafiExportConfig) *LiveConfig {
	return &LiveConfig{cfg: c}
}

// Snapshot returns a copy of the current config under a read lock.
func (l *LiveConfig) Snapshot() config.VenafiExportConfig {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg
}

// Set replaces the current config under a write lock.
func (l *LiveConfig) Set(c config.VenafiExportConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cfg = c
}
