// Package privilege says whether conch may do what needs more than a
// user's rights, such as creating a TUN device, and how to get them.
package privilege

import "errors"

// ErrTUN is wrapped by every TUNError result, so callers can tell a
// missing privilege from other problems.
var ErrTUN = errors.New("没有创建 TUN 网卡的权限")
