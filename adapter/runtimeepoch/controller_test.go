package runtimeepoch

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestPublishFailureKeepsPreviousRuntimeCurrent(t *testing.T) {
	controller := New()
	var firstPublished, firstRetired, firstClosed atomic.Int32
	if _, err := controller.PrepareInitial(testRuntime(&firstPublished, &firstRetired, &firstClosed)); err != nil {
		t.Fatal(err)
	}
	firstID, err := controller.ActivateInitial()
	if err != nil {
		t.Fatal(err)
	}
	var failedClosed atomic.Int32
	failed := testRuntime(new(atomic.Int32), new(atomic.Int32), &failedClosed)
	failed.Publish = func() error { return errors.New("publish rejected") }
	if _, err = controller.Publish(failed); err == nil {
		t.Fatal("failed runtime publish succeeded")
	}
	if controller.CurrentID() != firstID || firstRetired.Load() != 0 {
		t.Fatalf("failed publish replaced/retired previous runtime: current=%d retired=%d", controller.CurrentID(), firstRetired.Load())
	}
	if failedClosed.Load() != 1 {
		t.Fatalf("failed runtime was not closed: %d", failedClosed.Load())
	}
	if _, lease, err := controller.Acquire(); err != nil {
		t.Fatal("previous runtime unavailable after failed publish: ", err)
	} else {
		lease.Release()
	}
	if err = controller.Close(); err != nil {
		t.Fatal(err)
	}
}

type testRouter struct{ adapter.Router }
type testDNSRouter struct{ adapter.DNSRouter }
type testDNSTransportManager struct{ adapter.DNSTransportManager }
type testOutboundManager struct{ adapter.OutboundManager }
type testProviderManager struct{ adapter.ProviderManager }
type testEndpointManager struct{ adapter.EndpointManager }

func testRuntime(published, retired, closed *atomic.Int32) Runtime {
	return Runtime{
		Router:       &testRouter{},
		DNSRouter:    &testDNSRouter{},
		DNSTransport: &testDNSTransportManager{},
		Outbound:     &testOutboundManager{},
		Provider:     &testProviderManager{},
		Endpoint:     &testEndpointManager{},
		Publish:      func() error { published.Add(1); return nil },
		Retire:       func() { retired.Add(1) },
		Close:        func() error { closed.Add(1); return nil },
	}
}

func TestPrepareActivatePublishAndDrain(t *testing.T) {
	controller := New()
	var firstPublished, firstRetired, firstClosed atomic.Int32
	if _, err := controller.PrepareInitial(testRuntime(&firstPublished, &firstRetired, &firstClosed)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.Acquire(); err == nil {
		t.Fatal("prepared epoch became visible before activation")
	}
	if _, err := controller.ActivateInitial(); err != nil {
		t.Fatal(err)
	}
	_, lease, err := controller.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	var nextPublished, nextRetired, nextClosed atomic.Int32
	if _, err = controller.Publish(testRuntime(&nextPublished, &nextRetired, &nextClosed)); err != nil {
		t.Fatal(err)
	}
	if firstPublished.Load() != 1 || firstRetired.Load() != 1 || firstClosed.Load() != 0 {
		t.Fatalf("unexpected first epoch state: publish=%d retire=%d close=%d", firstPublished.Load(), firstRetired.Load(), firstClosed.Load())
	}
	lease.Release()
	waitAtomic(t, &firstClosed, 1)
	if err = controller.Close(); err != nil {
		t.Fatal(err)
	}
	if nextRetired.Load() != 1 || nextClosed.Load() != 1 {
		t.Fatalf("current epoch did not retire cleanly: retire=%d close=%d", nextRetired.Load(), nextClosed.Load())
	}
}

func TestConcurrentAcquirePublishRelease(t *testing.T) {
	controller := New()
	var published, retired, closed atomic.Int32
	if _, err := controller.PrepareInitial(testRuntime(&published, &retired, &closed)); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ActivateInitial(); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 200 {
				_, lease, err := controller.Acquire()
				if err == nil {
					lease.Release()
				}
			}
		}()
	}
	for range 50 {
		if _, err := controller.Publish(testRuntime(&published, &retired, &closed)); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
	if published.Load() != 51 || retired.Load() != 51 || closed.Load() != 51 {
		t.Fatalf("epoch lifecycle mismatch: publish=%d retire=%d close=%d", published.Load(), retired.Load(), closed.Load())
	}
}

func waitAtomic(t *testing.T, value *atomic.Int32, expected int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if value.Load() == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("value did not reach %d: %d", expected, value.Load())
}
