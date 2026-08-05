package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestInboundInterfaceItem(t *testing.T) {
	item := NewInboundInterfaceItem([]string{"eth0", "pa-us"})
	if !item.Match(&adapter.InboundContext{InboundInterface: "pa-us"}) {
		t.Fatal("expected pa-us to match")
	}
	if item.Match(&adapter.InboundContext{InboundInterface: "pa-jp"}) {
		t.Fatal("did not expect pa-jp to match")
	}
}
