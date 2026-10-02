package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/xiongnemo/conch/internal/kernels"
	"github.com/xiongnemo/conch/internal/paths"
	"github.com/xiongnemo/conch/internal/platform/privilege"
)

func newKernelCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "kernel", Short: "管理内核（下载、校验、查看路径）"}
	cmd.AddCommand(newKernelInstallCmd(), newKernelPathCmd(), newKernelGeodataCmd(), newKernelSetcapCmd())
	return cmd
}

func newKernelInstallCmd() *cobra.Command {
	o := kernels.InstallOptions{Target: kernels.Host()}
	var geodata bool
	cmd := &cobra.Command{
		Use:   "install [mihomo|xray]",
		Short: "下载并校验内核",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Kernel = "mihomo"
			if len(args) == 1 {
				o.Kernel = args[0]
			}
			o.Dir = paths.DataDir()
			o.Log = cmd.ErrOrStderr()
			inst, err := kernels.Install(cmd.Context(), o)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已安装 %s %s：%s\n", inst.Kernel, inst.Version, inst.Path)
			if geodata {
				return kernels.FetchGeodata(cmd.Context(), nil, o.Kernel, o.Mirror, paths.KernelHome(o.Kernel), cmd.ErrOrStderr())
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.Version, "version", "", "版本（默认使用内置清单推荐的版本）")
	f.StringVar(&o.Asset, "asset", "", "指定安装包文件名，例如 mihomo-linux-amd64-compatible-v1.19.32.gz")
	f.StringVar(&o.Mirror, "mirror", "", "GitHub 下载镜像前缀，例如 https://ghfast.top（默认用环境变量 CONCH_MIRROR）")
	f.BoolVar(&geodata, "geodata", false, "同时下载 geodata")
	return cmd
}

func newKernelPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path [mihomo|xray]",
		Short: "显示当前内核的路径",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kernel := "mihomo"
			if len(args) == 1 {
				kernel = args[0]
			}
			inst, err := kernels.Current(paths.DataDir(), kernel, kernels.Host().OS)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), inst.Path)
			return nil
		},
	}
}

func newKernelGeodataCmd() *cobra.Command {
	var mirror, dir string
	cmd := &cobra.Command{
		Use:   "geodata [mihomo|xray]",
		Short: "下载内核需要的 geodata（GeoIP / GeoSite）并校验",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kernel := "mihomo"
			if len(args) == 1 {
				kernel = args[0]
			}
			if dir == "" {
				dir = paths.KernelHome(kernel)
			}
			if err := kernels.FetchGeodata(cmd.Context(), nil, kernel, mirror, dir, cmd.ErrOrStderr()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "geodata 已保存到 %s\n", dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&mirror, "mirror", "", "GitHub 下载镜像前缀，例如 https://ghfast.top（默认用环境变量 CONCH_MIRROR）")
	cmd.Flags().StringVar(&dir, "dir", "", "保存目录（默认是内核的工作目录）")
	return cmd
}

func newKernelSetcapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setcap [mihomo]",
		Short: "给内核加上创建 TUN 网卡的权限（Linux，需要 sudo）",
		Long: `给已安装的内核加上 cap_net_admin、cap_net_bind_service 和 cap_net_raw 权限，
这样普通用户运行的 daemon 也能开启 TUN。升级内核后需要重新运行一次。`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kernel := "mihomo"
			if len(args) == 1 {
				kernel = args[0]
			}
			dataDir := paths.DataDir()
			// Under sudo, the kernel is the invoking user's, not root's.
			if name := os.Getenv("SUDO_USER"); os.Geteuid() == 0 && name != "" && os.Getenv("CONCH_DATA_DIR") == "" {
				u, err := user.Lookup(name)
				if err != nil {
					return err
				}
				dataDir = filepath.Join(u.HomeDir, ".local", "share", "conch")
			}
			inst, err := kernels.Current(dataDir, kernel, kernels.Host().OS)
			if err != nil {
				return err
			}
			if err := privilege.SetTUNCaps(inst.Path); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已给 %s 加上网络权限，现在可以开启 TUN 了\n", inst.Path)
			return nil
		},
	}
}
