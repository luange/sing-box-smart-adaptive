package adaptive

import (
	"testing"
	"time"
)

func TestStartupProbeTasksBoundAndStaggerInitialCoverage(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pool := &AdaptivePool{
		probeConcurrency: 2,
		probeCoverage:    10 * time.Minute,
		probeTimeout:     5 * time.Second,
		probeURL:         "https://example.com/",
	}
	snapshot := &ExecutionSnapshot{RuntimeEpochID: 1, CatalogRevision: 1, Generation: 1}
	for _, value := range []byte{5, 1, 4, 2, 3} {
		id := NodeID{value}
		snapshot.Candidates = append(snapshot.Candidates, Candidate{ID: id, Handle: NodeHandle{NodeID: id, Slot: uint64(value), Version: 1}})
	}

	tasks := pool.startupProbeTasks(snapshot, now)
	if len(tasks) != 5 {
		t.Fatalf("unexpected task count: %d", len(tasks))
	}
	for index, task := range tasks {
		if task.Key.NodeID[0] != byte(index+1) {
			t.Fatalf("startup order is not stable: index=%d node=%d", index, task.Key.NodeID[0])
		}
		if task.Interval != 10*time.Minute {
			t.Fatalf("periodic coverage was not retained: %s", task.Interval)
		}
		if task.FailureInterval != time.Minute {
			t.Fatalf("failed node did not get bounded fast recovery: %s", task.FailureInterval)
		}
	}
	if !tasks[0].DueAt.Equal(now) || !tasks[1].DueAt.Equal(now) {
		t.Fatal("the first worker-sized probe wave was delayed")
	}
	wantOffsets := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second}
	for index, want := range wantOffsets {
		if got := tasks[index+2].DueAt.Sub(now); got != want {
			t.Fatalf("unexpected stagger at %d: got=%s want=%s", index, got, want)
		}
	}
	if snapshot.Candidates[0].ID[0] != 5 {
		t.Fatal("startup scheduling mutated the committed catalog order")
	}
}

func TestPeriodicProbeFailureUsesFastRecoveryThenReturnsToCoverage(t *testing.T) {
	task := ProbeTask{Interval: 10 * time.Minute, FailureInterval: time.Minute}
	if got := nextPeriodicProbeInterval(task, ProbeResult{Outcome: OutcomeFailure}); got != time.Minute {
		t.Fatalf("failure did not select recovery interval: %s", got)
	}
	task.FailureStreak = 1
	if got := nextPeriodicProbeInterval(task, ProbeResult{Outcome: OutcomeFailure}); got != 5*time.Minute {
		t.Fatalf("second failure did not back off to five minutes: %s", got)
	}
	task.FailureStreak = 2
	if got := nextPeriodicProbeInterval(task, ProbeResult{Outcome: OutcomeFailure}); got != 10*time.Minute {
		t.Fatalf("persistent failure did not return to coverage interval: %s", got)
	}
	for _, outcome := range []ObservationOutcome{OutcomeSuccess, OutcomeDeferred, OutcomeBlocked} {
		if got := nextPeriodicProbeInterval(task, ProbeResult{Outcome: outcome}); got != 10*time.Minute {
			t.Fatalf("%s unexpectedly changed normal coverage: %s", outcome, got)
		}
	}
}

func TestStartupProbeTasksUseCoverageBoundForShortIntervals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pool := &AdaptivePool{probeConcurrency: 1, probeCoverage: 20 * time.Second, probeTimeout: time.Second}
	snapshot := &ExecutionSnapshot{RuntimeEpochID: 1, CatalogRevision: 1, Generation: 1}
	for value := byte(1); value <= 3; value++ {
		id := NodeID{value}
		snapshot.Candidates = append(snapshot.Candidates, Candidate{ID: id, Handle: NodeHandle{NodeID: id, Slot: uint64(value), Version: 1}})
	}

	tasks := pool.startupProbeTasks(snapshot, now)
	if got := tasks[len(tasks)-1].DueAt.Sub(now); got != 2*time.Second {
		t.Fatalf("short coverage interval was over-delayed: %s", got)
	}
}
