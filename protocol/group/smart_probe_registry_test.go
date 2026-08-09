package group

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/stretchr/testify/require"
)

func TestSmartProbeRegistrySingleflightAndTTL(t *testing.T) {
	registry := newSmartProbeRegistry(context.Background())
	defer registry.close()
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	registry.probe = func(context.Context, string, adapter.Outbound) (uint16, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return 42, nil
	}
	key := smartProbeKey("credential-sensitive-node", "https://probe.invalid/", time.Second)
	var wait sync.WaitGroup
	results := make(chan uint16, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			delay, err := registry.run(context.Background(), key, "https://probe.invalid/", time.Second, time.Minute, nil)
			require.NoError(t, err)
			results <- delay
		}()
	}
	<-started
	close(release)
	wait.Wait()
	close(results)
	for delay := range results {
		require.Equal(t, uint16(42), delay)
	}
	require.Equal(t, int32(1), calls.Load())

	delay, err := registry.run(context.Background(), key, "https://probe.invalid/", time.Second, time.Minute, nil)
	require.NoError(t, err)
	require.Equal(t, uint16(42), delay)
	require.Equal(t, int32(1), calls.Load(), "fresh result should be shared across groups")
}

func TestSmartProbeRegistryFailureIsOpaqueAndBounded(t *testing.T) {
	registry := newSmartProbeRegistry(context.Background())
	defer registry.close()
	registry.probe = func(context.Context, string, adapter.Outbound) (uint16, error) {
		return 0, errors.New("credential-bearing upstream failure")
	}
	key := smartProbeKey("node", "https://probe.invalid/?token=secret", time.Second)
	_, err := registry.run(context.Background(), key, "https://probe.invalid/?token=secret", time.Second, time.Minute, nil)
	require.ErrorIs(t, err, errSharedSmartProbeFailed)
	require.NotContains(t, err.Error(), "secret")
	require.Len(t, registry.entries, 1)
	for storedKey := range registry.entries {
		require.NotContains(t, storedKey, "token")
		require.NotContains(t, storedKey, "secret")
	}
}

func TestSmartProbeRegistryProcessLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	registryA, releaseA := acquireSmartProbeRegistry(ctx)
	registryB, releaseB := acquireSmartProbeRegistry(ctx)
	require.Same(t, registryA, registryB)
	releaseA()
	require.NotNil(t, registryB.entries)
	releaseB()

	registryC, releaseC := acquireSmartProbeRegistry(ctx)
	require.NotSame(t, registryA, registryC)
	releaseC()
	cancel()
}
