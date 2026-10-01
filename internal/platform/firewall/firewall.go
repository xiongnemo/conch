// Package firewall lets a kernel accept the connections TUN hands it: on
// Windows, the system stack's are inbound connections to the kernel.
package firewall

import "slices"

// Kernels that may run TUN, which rules are named after.
var kernels = []string{"mihomo", "sing-box", "xray"}

func ruleName(kernel string) string { return "Nautilus " + kernel }

func known(kernel string) bool { return slices.Contains(kernels, kernel) }
