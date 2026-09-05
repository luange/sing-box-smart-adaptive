//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"unsafe"
)

func TestSpliceABI(t *testing.T) {
	if unsafe.Sizeof(spliceKey{}) != spliceKeySize {
		t.Fatalf("spliceKey size=%d want %d", unsafe.Sizeof(spliceKey{}), spliceKeySize)
	}
	if unsafe.Sizeof(spliceControl{}) != spliceControlSize {
		t.Fatalf("spliceControl size=%d want %d", unsafe.Sizeof(spliceControl{}), spliceControlSize)
	}
	// Q10: kernel enum slots 0..5 + COUNT == 6 (pairs with native/splice.bpf.c).
	if spliceStatCount != 6 {
		t.Fatalf("spliceStatCount=%d want 6", spliceStatCount)
	}
}

func TestOutVerdictABI(t *testing.T) {
	if unsafe.Sizeof(outVerdictKey{}) != outVerdictKeySize {
		t.Fatalf("outVerdictKey size=%d want %d", unsafe.Sizeof(outVerdictKey{}), outVerdictKeySize)
	}
	if unsafe.Sizeof(outVerdictValue{}) != outVerdictValueSize {
		t.Fatalf("outVerdictValue size=%d want %d", unsafe.Sizeof(outVerdictValue{}), outVerdictValueSize)
	}
	if unsafe.Sizeof(outVerdictControl{}) != outVerdictControlSize {
		t.Fatalf("outVerdictControl size=%d want %d", unsafe.Sizeof(outVerdictControl{}), outVerdictControlSize)
	}
}
