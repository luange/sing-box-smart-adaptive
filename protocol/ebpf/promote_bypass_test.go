//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestVerdictPromoteBypassDefaultOnLearn(t *testing.T) {
	opts := verdictLearnOptionsFrom(option.EBPFVerdictOptions{Mode: "learn"})
	if !opts.promoteBypass {
		t.Fatal("promote_bypass should default true in learn mode")
	}
	if opts.ttl != 5*time.Minute {
		t.Fatalf("ttl default %v", opts.ttl)
	}
	f := false
	opts = verdictLearnOptionsFrom(option.EBPFVerdictOptions{Mode: "learn", PromoteBypass: &f})
	if opts.promoteBypass {
		t.Fatal("explicit false must win")
	}
	opts = verdictLearnOptionsFrom(option.EBPFVerdictOptions{Mode: "off"})
	if opts.promoteBypass {
		t.Fatal("off mode must not promote")
	}
}
