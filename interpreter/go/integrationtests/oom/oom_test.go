// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oom // import "go.opentelemetry.io/ebpf-profiler/interpreter/go/integrationtests/oom"

import (
	"testing"
	"time"
)

func TestOOM(t *testing.T) {
	// wait long enough for process start to register
	time.Sleep(1 * time.Second)
	var data [][]byte
	for {
		data = append(data, make([]byte, 1_000_000))
		time.Sleep(1 * time.Millisecond)
	}
}
