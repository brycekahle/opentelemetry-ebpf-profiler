//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests

import (
	"bytes"
	"context"
	_ "embed"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/collector"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/probes/oom"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

var (
	//go:embed go_oom
	go_oom []byte
)

func Test_GoOOM(t *testing.T) {
	t.Cleanup(func() {
		out, err := exec.Command("swapon", "-a").CombinedOutput()
		if err != nil {
			t.Logf("swapon -a: %s: %s", err, out)
		}
	})
	require.NoError(t, exec.Command("swapoff", "-a").Run())

	exe, err := os.CreateTemp(t.TempDir(), "go_oom")
	require.NoError(t, err)
	defer os.Remove(exe.Name())

	_, err = exe.Write(go_oom)
	require.NoError(t, err)
	require.NoError(t, exe.Close())
	require.NoError(t, os.Chmod(exe.Name(), 0o755))

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	debug.SetTraceback("all")
	metrics.Start(noop.Meter{})

	log.SetLevel(slog.LevelDebug)
	cfg := interpreterconfig.NoInterpreters()
	cfg.Go.Disabled = false
	cfg.Go.Labels.Disabled = true
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		InterpretersConfig:     cfg,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		VerboseMode:            true,
	})
	require.NoError(t, err)
	defer trc.Close()

	trc.StartPIDEventProcessor(ctx)
	require.NoError(t, trc.AttachTracer(allCPUs))

	t.Log("Attached tracer program")
	require.NoError(t, trc.AttachSchedMonitor())

	f := oom.NewFactory()
	oomExt, err := f.Create(ctx, extension.Settings{
		ID: component.MustNewID("oom"),
	}, nil)
	require.NoError(t, err)
	probe := oomExt.(collector.ProbeExtension).Probe()
	oomProbe := probe.(*oom.Probe)

	err = trc.Enable(ctx, probe)
	require.NoError(t, err)
	t.Logf("looking for origin %d", oomProbe.Origin())

	t.Cleanup(func() {
		err := probe.Unload()
		if err != nil {
			t.Logf("oom unload failed: %s", err)
		}
	})

	traceCh := make(chan *libpf.EbpfTrace)
	require.NoError(t, trc.StartMapMonitors(ctx, traceCh))

	var pid int
	var b bytes.Buffer
	g, groupCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		cmd := exec.CommandContext(groupCtx, "systemd-run", "--scope", "-p", "MemoryLimit=5M", exe.Name())
		cmd.Stdout = &b
		cmd.Stderr = &b
		runErr := cmd.Start()
		if runErr != nil {
			return runErr
		}
		pid = cmd.Process.Pid
		t.Logf("started go_oom pid=%d", pid)
		// we must wait for systemd-run to exec into the target
		time.Sleep(1 * time.Millisecond)
		trc.SyncProcess(uint32(pid), uint32(pid))
		waitErr := cmd.Wait()
		t.Logf("exited go_oom pid=%d", pid)
		return waitErr
	})

	ok := false
TraceLoop:
	for {
		select {
		case <-ctx.Done():
			assert.Fail(t, "timed out waiting for OOM trace")
			break TraceLoop
		case trace := <-traceCh:
			if trace == nil || trace.Origin != oomProbe.Origin() {
				continue
			}
			assert.Equal(t, libpf.NewCommFromString(filepath.Base(exe.Name())), trace.Comm)
			if assert.NotEmpty(t, trace.ContextValues) {
				assert.NotZero(t, trace.ContextValues[0])
			}
			trc.HandleTrace(trace)
			snapshots := trc.CollectSnapshots()
			if assert.Len(t, snapshots, 1) {
				if assert.NotEmpty(t, snapshots[0].Samples) {
					for sidx, sample := range snapshots[0].Samples {
						assert.Equal(t, pid, int(sample.PID), "sample %d", sidx)
						assert.False(t, sample.TraceHash.IsZero(), "sample %d", sidx)
						assert.NotEmpty(t, sample.Frames, "sample %d", sidx)
						assert.Len(t, sample.ContextValues, 3, "sample %d", sidx)
					}
				}
			}
			ok = !t.Failed()
			break TraceLoop
		}
	}
	require.True(t, ok, "valid OOM not received")

	err = g.Wait()
	output := b.Bytes()
	require.Error(t, err)
	require.NotErrorIs(t, err, context.DeadlineExceeded)

	var exiterr *exec.ExitError
	require.ErrorAs(t, err, &exiterr, output)

	status, sok := exiterr.Sys().(syscall.WaitStatus)
	require.True(t, sok, output)

	if status.Signaled() {
		require.Equal(t, unix.SIGKILL, status.Signal(), output)
	} else {
		require.Equal(t, 128+unix.SIGKILL, status.ExitStatus(), output)
	}
}
