package privilege

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Capabilities a kernel needs for TUN with automatic routes: configuring
// interfaces and routes, and binding DNS on port 53.
const (
	capNetBindService = 10
	capNetAdmin       = 12
	capNetRaw         = 13
	tunCaps           = 1<<capNetAdmin | 1<<capNetBindService | 1<<capNetRaw
)

// TUNError returns nil if the kernel at bin can create a TUN device: when
// conch runs as root or with ambient capabilities (the systemd
// service), or when the binary itself carries the capabilities.
func TUNError(bin string) error {
	if os.Geteuid() == 0 || processHas("CapAmb", capNetAdmin) {
		return nil
	}
	if caps, ok := fileCaps(bin); ok && caps&(1<<capNetAdmin) != 0 {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		self = "conch"
	}
	return fmt.Errorf("%w。可以给内核加上网络权限（升级内核后要重新做一次）：\n  sudo setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep %s\n也可以用 sudo %s service install 安装成系统服务", ErrTUN, bin, self)
}

// RoutesError returns nil if conch itself may change the system's
// routes, which it does for kernels that only bring a TUN device up (xray).
func RoutesError() error {
	if os.Geteuid() == 0 || processHas("CapEff", capNetAdmin) {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		self = "conch"
	}
	return fmt.Errorf("%w：xray 只会建 TUN 网卡，系统路由要由 conch 来改，所以 conch 自己也需要管理网络的权限。可以用 sudo 运行 conch daemon，或者 sudo %s service install 安装成系统服务", ErrTUN, self)
}

// processHas reports whether a capability is in one of this process's
// sets in /proc/self/status (CapEff, CapAmb, …).
func processHas(set string, capability int) bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), set+":"); ok {
			bits, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && bits&(1<<capability) != 0
		}
	}
	return false
}

const (
	vfsCapRevisionMask = 0xFF000000
	vfsCapRevision2    = 0x02000000
	vfsCapRevision3    = 0x03000000
	vfsCapEffective    = 0x1
)

// fileCaps reads the permitted capabilities a binary gets when executed,
// if they are also effective (setcap's +ep).
func fileCaps(path string) (uint64, bool) {
	buf := make([]byte, 24)
	n, err := unix.Getxattr(path, "security.capability", buf)
	if err != nil || n < 20 {
		return 0, false
	}
	return parseFileCaps(buf[:n])
}

func parseFileCaps(b []byte) (uint64, bool) {
	if len(b) < 20 {
		return 0, false
	}
	magic := binary.LittleEndian.Uint32(b)
	if rev := magic & vfsCapRevisionMask; rev != vfsCapRevision2 && rev != vfsCapRevision3 || magic&vfsCapEffective == 0 {
		return 0, false
	}
	low, high := binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[12:])
	return uint64(high)<<32 | uint64(low), true
}

// SetTUNCaps gives the binary the capabilities TUN needs, like
// `setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep`. It needs root.
func SetTUNCaps(path string) error {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b, vfsCapRevision2|vfsCapEffective)
	binary.LittleEndian.PutUint32(b[4:], uint32(tunCaps))
	if err := unix.Setxattr(path, "security.capability", b, 0); err != nil {
		return fmt.Errorf("给 %s 设置权限：%w（需要用 sudo 运行）", path, err)
	}
	return nil
}
