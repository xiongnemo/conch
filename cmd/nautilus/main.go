// Command nautilus is a proxy shell: it compiles a routing-table profile
// into kernel configuration and manages the kernel.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// errReported means the details were already printed for the user.
var errReported = errors.New("reported")

func main() {
	root := &cobra.Command{
		Use:           "nautilus",
		Short:         "路由表式分流 + 多跳链式代理",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newDaemonCmd(), newTUICmd(), newPairCmd(), newEditCmd(), newServiceCmd(), newAgentCmd(), newStatusCmd(), newRouteCmd(), newSubCmd(), newImportCmd(), newCompileCmd(), newKernelCmd(), newPasswdCmd(), newSysProxyCmd(), newTUNCmd(), newDoctorCmd(), newEnvCmd(), newRunCmd(), &cobra.Command{
		Use:   "version",
		Short: "显示版本",
		Run:   func(cmd *cobra.Command, _ []string) { fmt.Fprintln(cmd.OutOrStdout(), version) },
	})
	if err := root.Execute(); err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintln(os.Stderr, "错误：", err)
		}
		os.Exit(1)
	}
}
