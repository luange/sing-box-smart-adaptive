package route

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group/adaptive"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestAdaptivePoolPreMatchReturnsToL4DataPath(t *testing.T) {
	metadata := &adapter.InboundContext{
		Network:     N.NetworkTCP,
		Destination: M.ParseSocksaddr("youtube.com:443"),
	}
	selected, action := new(Router).selectPreMatchOutbound(metadata, new(adaptive.AdaptivePool), 0)
	if selected != nil || action != adapter.PreMatchContinue {
		t.Fatalf("adaptive pool pre-match selected a leaf: selected=%v action=%v", selected, action)
	}
}
