package main

import (
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestAdaptivePoolPublishesAfterBoxStart(t *testing.T) {
	instance := startInstance(t, option.Options{
		Outbounds: []option.Outbound{
			{
				Type:    C.TypeDirect,
				Tag:     "direct-a",
				Options: new(option.DirectOutboundOptions),
			},
			{
				Type:    C.TypeDirect,
				Tag:     "direct-b",
				Options: new(option.DirectOutboundOptions),
			},
			{
				Type: C.TypeAdaptivePool,
				Tag:  "adaptive-start-test",
				Options: &option.AdaptivePoolOutboundOptions{
					GroupCommonOption: option.GroupCommonOption{Outbounds: []string{"direct-a", "direct-b"}},
					Shadow:            true,
					Probe:             option.AdaptivePoolProbeOptions{URL: "http://127.0.0.1:1/health"},
					State:             option.AdaptivePoolStateOptions{Path: filepath.Join(t.TempDir(), "state")},
				},
			},
		},
		Route: &option.RouteOptions{Final: "direct-a"},
	})

	outbound, loaded := instance.Outbound().Outbound("adaptive-start-test")
	require.True(t, loaded)
	group, loaded := outbound.(adapter.AdaptivePoolGroup)
	require.True(t, loaded)
	status := group.AdaptiveStatus()
	require.Equal(t, uint64(1), status.Generation)
	require.Equal(t, 2, status.CandidateCount)
	require.Equal(t, 2, status.ActiveBindingCount)
	require.NotZero(t, status.ProbeOwnerEpoch)
}
