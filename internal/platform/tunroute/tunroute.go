// Package tunroute points the system's routes at a TUN device, for kernels
// that only bring the device up and leave routing to the OS (xray).
//
// On Linux, a table of its own holds a default route into the device, and
// ip rules send everything there except packets the kernel itself sends,
// which carry Mark, and destinations more specific routes know (the LAN,
// VPNs): the same "suppress_prefixlength 0" rule wg-quick uses. DNS goes
// into the device even to the LAN, so the kernel answers every query.
package tunroute

// Mark is the fwmark on the kernel's own packets; the kernel's config sets
// it on every outbound. Table is the routing table holding the TUN's
// default route; rules use priorities Priority to Priority+4, ahead of the
// main table's (32766) and away from what sing-box and mihomo (9000s) and
// Tailscale (5200s) use. "CN" in ASCII, for conch.
const (
	Mark     = 0x434e
	Table    = 0x434e
	Priority = 17230
)
