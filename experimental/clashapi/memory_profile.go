package clashapi

import (
	"net/http"
	"runtime"
	"sort"
	"strings"

	"github.com/go-chi/render"
)

const memoryProfileResultLimit = 32

type HeapProfileEntry struct {
	Function string `json:"function"`
	Bytes    int64  `json:"bytes"`
	Objects  int64  `json:"objects"`
}

type HeapProfile struct {
	SampleRate int                `json:"sample_rate"`
	Entries    []HeapProfileEntry `json:"entries"`
}

type GoroutineProfileEntry struct {
	Function string `json:"function"`
	Count    int    `json:"count"`
}

type GoroutineProfile struct {
	Total   int                     `json:"total"`
	Entries []GoroutineProfileEntry `json:"entries"`
}

func memoryHeapProfile(w http.ResponseWriter, r *http.Request) {
	profiles := heapProfileSummary()
	render.JSON(w, r, profiles)
}

func memoryGoroutineProfile(w http.ResponseWriter, r *http.Request) {
	profiles := goroutineProfileSummary()
	render.JSON(w, r, profiles)
}

func heapProfileSummary() HeapProfile {
	size, _ := runtime.MemProfile(nil, true)
	records := make([]runtime.MemProfileRecord, size+16)
	for {
		count, ok := runtime.MemProfile(records, true)
		if ok {
			records = records[:count]
			break
		}
		records = make([]runtime.MemProfileRecord, count+16)
	}
	byFunction := make(map[string]HeapProfileEntry)
	for index := range records {
		record := &records[index]
		inuseBytes := record.AllocBytes - record.FreeBytes
		inuseObjects := record.AllocObjects - record.FreeObjects
		if inuseBytes <= 0 && inuseObjects <= 0 {
			continue
		}
		function := firstApplicationFrame(record.Stack())
		entry := byFunction[function]
		entry.Function = function
		entry.Bytes += inuseBytes
		entry.Objects += inuseObjects
		byFunction[function] = entry
	}
	entries := make([]HeapProfileEntry, 0, len(byFunction))
	for _, entry := range byFunction {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Bytes > entries[j].Bytes })
	if len(entries) > memoryProfileResultLimit {
		entries = entries[:memoryProfileResultLimit]
	}
	return HeapProfile{SampleRate: runtime.MemProfileRate, Entries: entries}
}

func goroutineProfileSummary() GoroutineProfile {
	size, _ := runtime.GoroutineProfile(nil)
	records := make([]runtime.StackRecord, size+16)
	for {
		count, ok := runtime.GoroutineProfile(records)
		if ok {
			records = records[:count]
			break
		}
		records = make([]runtime.StackRecord, count+16)
	}
	counts := make(map[string]int)
	for index := range records {
		counts[firstApplicationFrame(records[index].Stack())]++
	}
	entries := make([]GoroutineProfileEntry, 0, len(counts))
	for function, count := range counts {
		entries = append(entries, GoroutineProfileEntry{Function: function, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Count > entries[j].Count })
	if len(entries) > memoryProfileResultLimit {
		entries = entries[:memoryProfileResultLimit]
	}
	return GoroutineProfile{Total: len(records), Entries: entries}
}

func firstApplicationFrame(pcs []uintptr) string {
	frames := runtime.CallersFrames(pcs)
	for {
		frame, more := frames.Next()
		if frame.Function != "" && !strings.HasPrefix(frame.Function, "runtime.") {
			return frame.Function
		}
		if !more {
			break
		}
	}
	return "runtime"
}
