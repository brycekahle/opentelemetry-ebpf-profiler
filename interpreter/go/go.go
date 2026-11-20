// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import (
	"errors"
	"fmt"
	"go/version"
	"sync/atomic"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var (
	// compiler check to make sure the needed interfaces are satisfied
	_ interpreter.Data     = &goData{}
	_ interpreter.Instance = &goInstance{}
)

type goData struct {
	fileID    host.FileID
	goVersion string
	offsets   support.GoRuntimeOffsets

	pclntab *elfunwindinfo.Gopclntab
	// refs only tracks the pclntab lifetime.
	// without it there is nothing to reference-count.
	refs atomic.Int32
}

type goInstance struct {
	interpreter.InstanceStubs
	d *goData

	// Go symbolization metrics
	successCount atomic.Uint64
	failCount    atomic.Uint64
}

var errDecodeSymbol = errors.New("failed to decode symbol")
var errRuntimeIsCgoUnavailable = errors.New("runtime.iscgo value unavailable")

func (d *goData) unref() {
	if d.pclntab == nil {
		return
	}
	if d.refs.Add(-1) == 0 {
		_ = d.pclntab.Close()
	}
}

func (d *goData) String() string {
	return "Go " + d.goVersion
}

func (d *goData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	procOffsets := d.offsets
	if procOffsets.Mbuckets_addr != 0 {
		procOffsets.Mbuckets_addr = uint64(libpf.Address(procOffsets.Mbuckets_addr) + bias)
		log.Infof("attach go PID %d with mbuckets 0x%x", pid, procOffsets.Mbuckets_addr)
	}
	if err := ebpf.UpdateProcData(libpf.Go, pid, unsafe.Pointer(&procOffsets)); err != nil {
		return nil, err
	}
	if d.pclntab != nil {
		d.refs.Add(1)
	}
	return &goInstance{d: d}, nil
}

func (i *goInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	err := ebpf.DeleteProcData(libpf.Go, pid)
	i.d.unref()
	return err
}

func (d *goData) Unload(_ interpreter.EbpfHandler) {
	d.unref()
}

func GetLoader(cfg Config) interpreter.Loader {
	resources := []interpreter.InterpreterResource{{MapName: BPFMapName}}
	return interpreter.NewLoader(
		func(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
			return loader(cfg, info)
		},
		resources,
	)
}

func loader(cfg Config, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	file, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	if !file.IsGolang() {
		return nil, nil
	}
	if !file.IsExecutable() {
		// Go plugins are shared objects that share the runtime with the main
		// binary. The offsets we need are determined by the main binary so there
		// is no reason to create a duplicate instance for a plugin.
		log.Debugf("file %s is a Go shared library, skipping", info.FileName())
		return nil, nil
	}

	goVersion := file.GoVersion()
	if goVersion == "" {
		// unable to extract, usually limited to old coredump tests
		goVersion = "go1.16"
		log.Debugf("file %s go version failed, assuming: %v", info.FileName(), goVersion)
	} else {
		log.Debugf("file %s detected as go version %s", info.FileName(), goVersion)
	}

	if version.Compare(goVersion, "go1.28") >= 0 {
		return nil, fmt.Errorf("unsupported Go version %s (need >= 1.13 and <= 1.27)", goVersion)
	}

	d := &goData{
		fileID:    info.FileID(),
		goVersion: goVersion,
		offsets:   getOffsets(goVersion),
	}

	pclntab, err := elfunwindinfo.NewGopclntab(file)
	if err == nil {
		defer func() {
			if pclntab != nil {
				pclntab.Close()
			}
		}()

		tlsOffset, err := extractTLSGOffset(file, pclntab)
		switch {
		case errors.Is(err, libpf.ErrSymbolNotFound):
			log.Warnf("failed to lookup symbol in %s: %v", info.FileName(), err)
		case errors.Is(err, errDecodeSymbol), errors.Is(err, errRuntimeIsCgoUnavailable):
			log.Debugf("In %s: %v", info.FileName(), err)
		case errors.Is(err, nil):
			d.offsets.Tls_offset = tlsOffset
		default:
			log.Warnf("failed to extract TLS offset: %s", err)
		}

		if !cfg.IsSymbolizationDisabled() {
			d.pclntab = pclntab
			d.refs.Store(1)
			pclntab = nil
		}
	}

	if !cfg.IsOOMDisabled() {
		mbucketsAddr, err := extractMbucketsAddress(file)
		if err != nil {
			return nil, fmt.Errorf("failed to extract mbuckets offset: %w", err)
		}
		if mbucketsAddr != 0 {
			log.Infof("file %s mbuckets at 0x%x", info.FileName(), mbucketsAddr)
		}
		d.offsets.Mbuckets_addr = mbucketsAddr
	}

	log.Infof("file %s go version %s", info.FileName(), goVersion)
	return d, nil
}
