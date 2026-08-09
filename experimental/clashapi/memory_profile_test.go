package clashapi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryProfilesAreAggregatedAndBounded(t *testing.T) {
	heap := heapProfileSummary()
	require.Positive(t, heap.SampleRate)
	require.LessOrEqual(t, len(heap.Entries), memoryProfileResultLimit)
	for _, entry := range heap.Entries {
		require.NotEmpty(t, entry.Function)
		require.NotContains(t, entry.Function, "?")
	}
	goroutines := goroutineProfileSummary()
	require.Positive(t, goroutines.Total)
	require.NotEmpty(t, goroutines.Entries)
	require.LessOrEqual(t, len(goroutines.Entries), memoryProfileResultLimit)
}
