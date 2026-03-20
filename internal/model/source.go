package model

import "time"

type SourceHealth struct {
	Name            string    `json:"name"`
	Type            string    `json:"type"` // "zeek_file", "corelight", "active_scan"
	Status          string    `json:"status"` // "running", "stopped", "error"
	CertsDiscovered int       `json:"certs_discovered"`
	ObservationsTotal int     `json:"observations_total"`
	LastRun         time.Time `json:"last_run"`
	LastError       string    `json:"last_error,omitempty"`
}

type IngestionState struct {
	SourceName string    `json:"source_name"`
	Cursor     string    `json:"cursor"` // File offset, API cursor, etc.
	UpdatedAt  time.Time `json:"updated_at"`
}

type PCAPJob struct {
	ID          string     `json:"id"`
	Filename    string     `json:"filename"`
	FileSize    int64      `json:"file_size"`
	Status      string     `json:"status"`
	CertsFound  int        `json:"certs_found"`
	CertsNew    int        `json:"certs_new"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}
