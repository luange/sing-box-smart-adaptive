package clashapi

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

// API created by Clash.Meta

func (s *Server) setupMetaAPI(r chi.Router) {
	if s.logDebug {
		r := chi.NewRouter()
		r.Put("/gc", func(w http.ResponseWriter, r *http.Request) {
			debug.FreeOSMemory()
		})
		r.Mount("/", middleware.Profiler())
	}
	r.Get("/memory", memory(s.ctx))
	r.Get("/memory/details", memoryDetails(s))
	r.Get("/memory/heap", memoryHeapProfile)
	r.Get("/memory/goroutines", memoryGoroutineProfile)
	r.Mount("/group", groupRouter(s))
	r.Mount("/upgrade", upgradeRouter(s))
}

type MemoryDetails struct {
	Memory
	HeapAlloc           uint64  `json:"heap_alloc"`
	HeapInuse           uint64  `json:"heap_inuse"`
	HeapIdle            uint64  `json:"heap_idle"`
	HeapReleased        uint64  `json:"heap_released"`
	HeapIdleUnreleased  uint64  `json:"heap_idle_unreleased"`
	HeapObjects         uint64  `json:"heap_objects"`
	StackInuse          uint64  `json:"stack_inuse"`
	Sys                 uint64  `json:"sys"`
	TotalAlloc          uint64  `json:"total_alloc"`
	Mallocs             uint64  `json:"mallocs"`
	Frees               uint64  `json:"frees"`
	NextGC              uint64  `json:"next_gc"`
	NumGC               uint32  `json:"num_gc"`
	PauseTotalNS        uint64  `json:"pause_total_ns"`
	GCCPUFraction       float64 `json:"gc_cpu_fraction"`
	Goroutines          int     `json:"goroutines"`
	ReclaimEnabled      bool    `json:"reclaim_enabled"`
	ReclaimCount        uint64  `json:"reclaim_count"`
	LastReclaimUnix     int64   `json:"last_reclaim_unix"`
	LastReclaimReleased uint64  `json:"last_reclaim_released"`
}

func currentMemoryDetails(s *Server) MemoryDetails {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	details := MemoryDetails{
		Memory:             Memory{Inuse: stats.StackInuse + stats.HeapInuse + stats.HeapIdle - stats.HeapReleased},
		HeapAlloc:          stats.HeapAlloc,
		HeapInuse:          stats.HeapInuse,
		HeapIdle:           stats.HeapIdle,
		HeapReleased:       stats.HeapReleased,
		HeapIdleUnreleased: stats.HeapIdle - stats.HeapReleased,
		HeapObjects:        stats.HeapObjects,
		StackInuse:         stats.StackInuse,
		Sys:                stats.Sys,
		TotalAlloc:         stats.TotalAlloc,
		Mallocs:            stats.Mallocs,
		Frees:              stats.Frees,
		NextGC:             stats.NextGC,
		NumGC:              stats.NumGC,
		PauseTotalNS:       stats.PauseTotalNs,
		GCCPUFraction:      stats.GCCPUFraction,
		Goroutines:         runtime.NumGoroutine(),
	}
	if s.memoryReclaim != nil {
		details.ReclaimEnabled = true
		details.ReclaimCount = s.memoryReclaim.reclaimCount.Load()
		details.LastReclaimUnix = s.memoryReclaim.lastReclaimUnix.Load()
		details.LastReclaimReleased = s.memoryReclaim.lastReleasedByte.Load()
	}
	return details
}

func memoryDetails(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, currentMemoryDetails(s))
	}
}

type Memory struct {
	Inuse   uint64 `json:"inuse"`
	OSLimit uint64 `json:"oslimit"` // maybe we need it in the future
}

func inuseMemory() uint64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return memStats.StackInuse + memStats.HeapInuse + memStats.HeapIdle - memStats.HeapReleased
}

func memory(ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var conn net.Conn
		if r.Header.Get("Upgrade") == "websocket" {
			var err error
			conn, _, _, err = ws.UpgradeHTTP(r, w)
			if err != nil {
				return
			}
			defer conn.Close()
		}

		if conn == nil {
			w.Header().Set("Content-Type", "application/json")
			render.Status(r, http.StatusOK)
		}

		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		buf := &bytes.Buffer{}
		var err error
		first := true
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			buf.Reset()

			inuse := inuseMemory()

			// make chat.js begin with zero
			// this is shit var,but we need output 0 for first time
			if first {
				first = false
				inuse = 0
			}
			if err := json.NewEncoder(buf).Encode(Memory{
				Inuse:   inuse,
				OSLimit: 0,
			}); err != nil {
				break
			}
			if conn == nil {
				_, err = w.Write(buf.Bytes())
				w.(http.Flusher).Flush()
			} else {
				err = wsutil.WriteServerText(conn, buf.Bytes())
			}
			if err != nil {
				break
			}
		}
	}
}
