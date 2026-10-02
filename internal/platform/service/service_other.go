//go:build !linux && !darwin && !windows

package service

import "errors"

var errUnsupported = errors.New("conch 还不能在这个系统上把自己装成服务")

func SystemLayout() Layout { return Layout{} }

func Install(Options) error { return errUnsupported }

func Uninstall(Options) error { return errUnsupported }

func Status(Options) (string, error) { return "", errUnsupported }
