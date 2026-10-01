//go:build !linux && !darwin && !windows

package sysproxy

func enable(int) (Snapshot, error) { return "", ErrUnsupported }
func restore(Snapshot) error       { return ErrUnsupported }
func current() (Status, error)     { return Status{}, ErrUnsupported }
