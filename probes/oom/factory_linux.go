// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package oom // import "go.opentelemetry.io/ebpf-profiler/probes/oom"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"go.opentelemetry.io/ebpf-profiler/probes/oom/internal/metadata"
)

// NewFactory returns an extension.Factory for the oom profiling extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		func() component.Config { return &struct{}{} },
		createExtension,
		metadata.ExtensionsStability,
	)
}

func createExtension(_ context.Context, _ extension.Settings, _ component.Config) (extension.Extension, error) {
	return &oomExtension{p: New()}, nil
}
