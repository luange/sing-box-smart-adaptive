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
	require.True(t, registry.failed(key, time.Minute), "a recent failure must be visible to every Smart group")
	registry.access.Lock()
	registry.entries[key].result.nextProbeAt = time.Now().Add(-time.Second)
	registry.access.Unlock()
	require.False(t, registry.failed(key, time.Nanosecond), "expired failures must not permanently suppress a node")
}

func TestSmartProbeCadence(t *testing.T) {
	require.Equal(t, 5*time.Minute, smartProbeCadence(true, 1, 0))
	require.Equal(t, 15*time.Minute, smartProbeCadence(true, 2, 0))
	require.Equal(t, 30*time.Minute, smartProbeCadence(true, 3, 0))
	require.Equal(t, 30*time.Second, smartProbeCadence(false, 0, 1))
	require.Equal(t, time.Minute, smartProbeCadence(false, 0, 2))
	require.Equal(t, 5*time.Minute, smartProbeCadence(false, 0, 3))
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

func TestSmartProbeRegistryBoundsProcessWideConcurrency(t *testing.T) {
	registry := newSmartProbeRegistry(context.Background())
	defer registry.close()
	var active atomic.Int32
	var maximum atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 5)
	registry.probe = func(context.Context, string, adapter.Outbound) (uint16, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
		return 10, nil
	}
	var workers sync.WaitGroup
	for index := range 5 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			key := smartProbeKey(string(rune('a'+index)), "https://probe.invalid/", time.Second)
			_, err := registry.run(context.Background(), key, "https://probe.invalid/", time.Second, time.Minute, nil)
			require.NoError(t, err)
		}()
	}
	<-started
	<-started
	<-started
	<-started
	require.Equal(t, int32(4), active.Load())
	require.Equal(t, int32(4), maximum.Load())
	close(release)
	workers.Wait()
	require.Equal(t, int32(4), maximum.Load())
}
