package ebpf

// Module A verdict constants (shared across cgo/stub builds).
// Mirror native/singbox_ebpf_out.h SB_OUT_VERDICT_*.
const (
	OutVerdictDIRECT = 1
	OutVerdictPROXY  = 2

	// BPF stats ARRAY indices (A2).
	outVerdictStatHits        = 0
	outVerdictStatExpired     = 1
	outVerdictStatGenMismatch = 2
	outVerdictStatCount       = 3

	// Default map capacity when option MaxEntries is 0.
	OutVerdictDefaultMaxEntries = 65536
)
