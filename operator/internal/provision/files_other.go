//go:build !linux

package provision

// Secure file handling uses Linux dirfd/O_NOFOLLOW semantics. Other platforms
// explicitly fail closed rather than silently using weaker path checks.
type secureFiles struct{}

func openFiles(string) (*secureFiles, error)              { return nil, ErrPlatform }
func (*secureFiles) Close() error                         { return nil }
func (*secureFiles) ReadFile(string, int) ([]byte, error) { return nil, ErrPlatform }
func (*secureFiles) WriteNew(string, artifacts) error     { return ErrPlatform }
