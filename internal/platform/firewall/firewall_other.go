//go:build !windows

package firewall

// Allow does nothing: only Windows' firewall stands between TUN and the
// kernel.
func Allow(kernel, program string) error { return nil }

// Remove does nothing outside Windows.
func Remove() {}
