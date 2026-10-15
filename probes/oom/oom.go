// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package oom implements a probe that
package oom // import "go.opentelemetry.io/ebpf-profiler/probes/oom"

import "C"
import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/zeebo/xxh3"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	oomOriginVar = "origin_id_oom"
)

var oomProfileType = &samples.TypeMetadata{
	SampleTypes: []samples.SampleType{
		{Type: "alloc_space", Unit: "bytes"},
		{Type: "inuse_space", Unit: "bytes"},
		{Type: "alloc_objects", Unit: "count"},
		{Type: "inuse_objects", Unit: "count"},
	},
	ReportValues:      true,
	OmitThreadContext: true,
	AppendValues: func(dst []int64, meta *samples.TraceEventMeta) []int64 {
		allocs := int64(meta.ContextValues[0])
		frees := int64(meta.ContextValues[1])
		size := int64(meta.ContextValues[2])
		inUse := allocs - frees
		return append(dst, allocs*size, inUse*size, allocs, inUse)
	},
}

// Probe implements tracer.Probe for OOM profiling.
type Probe struct {
	links      []link.Link
	bucketMmap *cebpf.Memory
	taskMap    *cebpf.Map

	// originOOM is the dynamically-assigned origin ID for OOM.
	originOOM uint16

	queuedProfiles []samples.SnapshotProfile
}

// New creates an oom probe.
func New() *Probe {
	return &Probe{}
}

func (op *Probe) Origin() uint16 {
	return op.originOOM
}

func (op *Probe) PreOrigins() []uint16 {
	return []uint16{op.originOOM}
}

func (op *Probe) PreHandleTrace(trace *libpf.EbpfTrace) bool {
	if len(trace.ContextValues) == 0 {
		return false
	}
	numBuckets := trace.ContextValues[0]

	var traceBuf [24]byte
	h := xxh3.New128()
	fileIDBytes := libpf.FileID{}.Bytes()

	// TODO this would be better if we didn't have to copy the data out
	var bucket support.GoBucket
	bucketSize := uint64(unsafe.Sizeof(bucket))
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&bucket)), bucketSize)

	entries := make([]samples.SnapshotSample, 0, numBuckets)
	for i := uint64(0); i < numBuckets; i++ {
		n, err := op.bucketMmap.ReadAt(buf, int64(i*bucketSize))
		if err != nil || uint64(n) < bucketSize {
			return false
		}

		allocObjects := bucket.Mem.Active.Allocs
		freeObjects := bucket.Mem.Active.Frees
		for j := 0; j < 3; j++ {
			allocObjects += bucket.Mem.Future[j].Allocs
			freeObjects += bucket.Mem.Future[j].Frees
		}

		sample := samples.SnapshotSample{
			PID:           trace.PID,
			Frames:        make(libpf.Frames, 0, bucket.Header.Nstk),
			ContextValues: []uint64{allocObjects, freeObjects, bucket.Header.Size},
		}

		h.Reset()
		for x := uint64(0); x < bucket.Header.Nstk; x++ {
			sample.Frames.Append(&libpf.Frame{
				Type:            libpf.GoFrame,
				AddressOrLineno: libpf.AddressOrLineno(bucket.Stk[x]),
			})
			_, _ = h.Write(fileIDBytes)
			n := putUint64(traceBuf[:], bucket.Stk[x])
			_, _ = h.Write(traceBuf[:n])
		}
		sample.TraceHash, _ = libpf.TraceHashFromBytes(h.Sum(traceBuf[:0]))

		entries = append(entries, sample)
	}

	op.queuedProfiles = append(op.queuedProfiles, samples.SnapshotProfile{
		ProfileType: oomProfileType,
		Samples:     entries,
	})
	return false
}

// ProduceSnapshots implements tracer.SnapshotSource. Returns queued OOM profiles.
func (op *Probe) ProduceSnapshots() []samples.SnapshotProfile {
	profiles := op.queuedProfiles
	op.queuedProfiles = nil
	return profiles
}

// Load implements tracer.Probe. It loads the oom eBPF programs.
func (op *Probe) Load(_ context.Context, reg tracer.ProbeRegistrar, pctx *tracer.ProbeContext) error {
	// Register origin ID. The eBPF program reads this from RODATA.
	var err error
	op.originOOM, err = reg.Register(oomProfileType)
	if err != nil {
		return fmt.Errorf("registering oom origin: %w", err)
	}

	// Load eBPF programs via ProbeContext.
	coll, err := pctx.CollectionSpecWith(
		[]string{"mbuckets_data", "profile_task"},
		[]string{"mark_victim_handler", "signal_deliver_handler"},
		[]string{oomOriginVar, "with_debug_output"},
	)
	if err != nil {
		return fmt.Errorf("building collection spec: %w", err)
	}

	// Set origin ID in RODATA so the eBPF program emits the correct value.
	if v, ok := coll.Variables[oomOriginVar]; ok {
		if err := v.Set(op.originOOM); err != nil {
			return fmt.Errorf("setting origin_id_oom: %w", err)
		}
	}
	// TODO use cfg.VerboseMode to set this
	if v, ok := coll.Variables["with_debug_output"]; ok {
		if err := v.Set(uint32(1)); err != nil {
			return fmt.Errorf("setting with_debug_output: %w", err)
		}
	}

	dataMap, err := cebpf.NewMap(coll.Maps["mbuckets_data"])
	if err != nil {
		return fmt.Errorf("creating mbuckets_data map: %w", err)
	}
	defer dataMap.Close()
	op.bucketMmap, err = dataMap.Memory()
	if err != nil {
		return fmt.Errorf("creating mbuckets_data mmap: %w", err)
	}

	op.taskMap, err = cebpf.NewMap(coll.Maps["profile_task"])
	if err != nil {
		return fmt.Errorf("creating profile_task map: %w", err)
	}

	if err := pctx.RewriteMaps(coll, map[string]*cebpf.Map{
		"mbuckets_data": dataMap,
		"profile_task":  op.taskMap,
	}); err != nil {
		return fmt.Errorf("rewriting maps: %w", err)
	}

	ebpfProgs := make(map[string]*cebpf.Program)
	progs := []tracer.ProgLoaderHelper{
		{
			Name:             "mark_victim_handler",
			Enable:           true,
			NoTailCallTarget: true,
		},
		{
			Name:             "signal_deliver_handler",
			Enable:           true,
			NoTailCallTarget: true,
		},
	}
	if err := pctx.LoadProbeUnwinders(coll, ebpfProgs, progs, 0); err != nil {
		return fmt.Errorf("loading oom eBPF programs: %w", err)
	}

	if p, ok := ebpfProgs["mark_victim_handler"]; ok {
		l, err := link.AttachTracing(link.TracingOptions{
			Program:    p,
			AttachType: cebpf.AttachTraceRawTp,
		})
		if err != nil {
			return fmt.Errorf("attaching mark_victim_handler: %w", err)
		}
		op.links = append(op.links, l)
	} else {
		return fmt.Errorf("missing mark_victim_handler")
	}
	if p, ok := ebpfProgs["signal_deliver_handler"]; ok {
		l, err := link.AttachTracing(link.TracingOptions{
			Program:    p,
			AttachType: cebpf.AttachTraceRawTp,
		})
		if err != nil {
			return fmt.Errorf("attaching signal_deliver_handler: %w", err)
		}
		op.links = append(op.links, l)
	} else {
		return fmt.Errorf("missing signal_deliver_handler")
	}
	return pctx.AddAttacher(op)
}

// Match implements processmanager.ProbeAttacher. The OOM probe matches all
// executable mappings because ...
func (op *Probe) Match(_ process.Process, _ *process.RawMapping) bool {
	return true
}

// Attach implements processmanager.ProbeAttacher.
func (op *Probe) Attach(_ process.Process, _ *process.RawMapping,
	_ libpf.FileID, _ *pfelf.Reference,
) error {
	return nil
}

// Detach implements processmanager.ProbeAttacher.
func (op *Probe) Detach(pid libpf.PID) {
	pid32 := uint32(pid)
	_ = op.taskMap.Delete(unsafe.Pointer(&pid32))
}

// Unload implements tracer.Probe.
func (op *Probe) Unload() error {
	var err error
	if op.taskMap != nil {
		err = errors.Join(err, op.taskMap.Close())
		op.taskMap = nil
	}
	for _, l := range op.links {
		err = errors.Join(err, l.Close())
	}
	op.links = nil
	return err
}

func putUint64(b []byte, v uint64) int {
	for i := range 8 {
		b[i] = byte(v)
		v >>= 8
		if v == 0 {
			return i + 1
		}
	}
	return 8
}
