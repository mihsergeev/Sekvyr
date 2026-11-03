//go:build linux

package provision

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type secureFiles struct{ fd int }

func components(path string) ([]string, error) {
	if path == "" || strings.ContainsAny(path, "\\\x00") || filepath.IsAbs(path) {
		return nil, ErrFiles
	}
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, ErrFiles
		}
	}
	return parts, nil
}
func checkDir(fd int) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return ErrFiles
	}
	return nil
}
func openFiles(path string) (*secureFiles, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrFiles
	}
	parts, err := components(strings.TrimPrefix(path, "/"))
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrFiles
	}
	for _, p := range parts {
		next, e := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, ErrFiles
		}
		fd = next
	}
	if checkDir(fd) != nil {
		unix.Close(fd)
		return nil, ErrFiles
	}
	return &secureFiles{fd: fd}, nil
}
func (s *secureFiles) Close() error { return unix.Close(s.fd) }
func (s *secureFiles) parent(path string) (int, string, error) {
	parts, err := components(path)
	if err != nil {
		return -1, "", err
	}
	fd, err := unix.Openat(s.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", ErrFiles
	}
	for _, p := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, "", ErrFiles
		}
		fd = next
		if checkDir(fd) != nil {
			unix.Close(fd)
			return -1, "", ErrFiles
		}
	}
	return fd, parts[len(parts)-1], nil
}
func (s *secureFiles) ReadFile(path string, max int) ([]byte, error) {
	fd, name, err := s.parent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrFiles
	}
	f := os.NewFile(uintptr(fileFD), "provision input")
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fileFD, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || st.Size > int64(max) || max < 0 {
		return nil, ErrFiles
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(b) > max {
		clear(b)
		return nil, ErrFiles
	}
	var after unix.Stat_t
	if unix.Fstat(fileFD, &after) != nil || after.Nlink != 1 || after.Size != st.Size || after.Mtim != st.Mtim || after.Ctim != st.Ctim {
		clear(b)
		return nil, ErrFiles
	}
	return b, nil
}
func (s *secureFiles) WriteNew(path string, a artifacts) error {
	parent, name, err := s.parent(path)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	if unix.Mkdirat(parent, name, 0700) != nil {
		return ErrFiles
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrFiles
	}
	defer unix.Close(fd)
	if checkDir(fd) != nil {
		return ErrFiles
	}
	var names []string
	for n := range a {
		if p, e := components(n); e != nil || len(p) != 1 {
			return ErrFiles
		}
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fileFD, e := unix.Openat(fd, n, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e != nil {
			return ErrFiles
		}
		f := os.NewFile(uintptr(fileFD), "provision artifact")
		e = unix.Fchmod(fileFD, 0600)
		if e == nil {
			_, e = f.Write(a[n])
		}
		if e == nil {
			e = f.Sync()
		}
		var st unix.Stat_t
		if e == nil && (unix.Fstat(fileFD, &st) != nil || st.Nlink != 1 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Uid != uint32(os.Geteuid())) {
			e = ErrFiles
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return ErrFiles
		}
	}
	if unix.Fsync(fd) != nil || unix.Fsync(parent) != nil {
		return ErrFiles
	}
	return nil
}
