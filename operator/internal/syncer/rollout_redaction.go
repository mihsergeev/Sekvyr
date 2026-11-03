package syncer

// A guard owns a short-lived copy of verified values. Formatting a result must
// never expose these bytes through nested interfaces or unexported fields.
func (rolloutGuard) String() string   { return "rollout authorization guard [redacted]" }
func (rolloutGuard) GoString() string { return "rollout authorization guard [redacted]" }
func (Result) String() string         { return "secret synchronization result [redacted]" }
func (Result) GoString() string       { return "secret synchronization result [redacted]" }
