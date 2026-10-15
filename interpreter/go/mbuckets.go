package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import (
	"errors"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func extractMbucketsAddress(file *pfelf.File) (uint64, error) {
	var mbucketsSym libpf.Symbol
	err := file.VisitSymbols(func(sym libpf.Symbol) bool {
		if sym.Name == "runtime.mbuckets" {
			mbucketsSym = sym
			return false
		}
		return true
	})
	if errors.Is(err, pfelf.ErrSectionNotPresent) {
		return 0, nil
	}
	if err != nil || mbucketsSym.Address == 0 {
		return 0, err
	}
	return uint64(mbucketsSym.Address), nil
}
