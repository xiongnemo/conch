//go:build !darwin

package sysdns

const needed = false

func enable(string) (Snapshot, error) { return "", nil }

func restore(Snapshot) error { return nil }
