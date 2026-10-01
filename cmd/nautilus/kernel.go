package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"nautilus/internal/kernels"
	"nautilus/internal/paths"
)

func newKernelCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "kernel", Short: "管理内核（下载、校验、查看路径）"}
	cmd.AddCommand(newKernelInstallCmd(), newKernelPathCmd(), newKernelGeodataCmd())
	return cmd
}

func newKernelInstallCmd() *cobra.Command {
	o := kernels.InstallOptions{Target: kernels.Host()}
	var geodata bool
	cmd := &cobra.Command{
		Use:   "install [mihomo]",
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
				return kernels.FetchGeodata(cmd.Context(), nil, o.Mirror, paths.KernelHome(o.Kernel), cmd.ErrOrStderr())
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.Version, "version", "", "版本（默认使用内置清单推荐的版本）")
	f.StringVar(&o.Asset, "asset", "", "指定安装包文件名，例如 mihomo-linux-amd64-compatible-v1.19.32.gz")
	f.StringVar(&o.Mirror, "mirror", "", "GitHub 下载镜像前缀，例如 https://ghfast.top")
	f.BoolVar(&geodata, "geodata", false, "同时下载 geodata")
	return cmd
}

func newKernelPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path [mihomo]",
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
		Use:   "geodata",
		Short: "下载 mihomo 的 geodata（GeoIP / GeoSite / ASN）并校验",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dir == "" {
				dir = paths.KernelHome("mihomo")
			}
			if err := kernels.FetchGeodata(cmd.Context(), nil, mirror, dir, cmd.ErrOrStderr()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "geodata 已保存到 %s\n", dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&mirror, "mirror", "", "GitHub 下载镜像前缀，例如 https://ghfast.top")
	cmd.Flags().StringVar(&dir, "dir", "", "保存目录（默认是内核的工作目录）")
	return cmd
}
