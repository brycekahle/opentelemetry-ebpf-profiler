// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package oom // import "go.opentelemetry.io/ebpf-profiler/probes/oom"

import (
	"context"

	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// oomExtension is an OTel Collector extension that exposes a tracer.Probe
// for use by the ebpf_profiler receiver.
type oomExtension struct {
	p tracer.Probe
}

func (e *oomExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *oomExtension) Shutdown(_ context.Context) error                { return nil }

// Probe returns the tracer.Probe that this extension provides.
func (e *oomExtension) Probe() tracer.Probe { return e.p }
