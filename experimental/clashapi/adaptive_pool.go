package clashapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func adaptivePoolRouter(server *Server) http.Handler {
	router := chi.NewRouter()
	router.Get("/", func(w http.ResponseWriter, request *http.Request) {
		statuses := make(map[string]adapter.AdaptivePoolStatus)
		for _, detour := range server.outbound.Outbounds() {
			if group, loaded := detour.(adapter.AdaptivePoolGroup); loaded {
				statuses[detour.Tag()] = group.AdaptiveStatus()
			}
		}
		render.JSON(w, request, map[string]any{"adaptive_pools": statuses})
	})
	router.Route("/{name}", func(router chi.Router) {
		router.Use(parseAdaptivePool(server))
		router.Get("/status", func(w http.ResponseWriter, request *http.Request) {
			group := request.Context().Value(ctxKeyAdaptivePool{}).(adapter.AdaptivePoolGroup)
			render.JSON(w, request, group.AdaptiveStatus())
		})
		router.Get("/events", streamAdaptivePoolEvents)
		router.Post("/probes", func(w http.ResponseWriter, request *http.Request) {
			group := request.Context().Value(ctxKeyAdaptivePool{}).(adapter.AdaptivePoolGroup)
			if err := group.TriggerAdaptiveProbe(request.Context()); err != nil {
				render.Status(request, http.StatusServiceUnavailable)
				render.JSON(w, request, newError(err.Error()))
				return
			}
			render.Status(request, http.StatusAccepted)
			render.JSON(w, request, map[string]string{"status": "scheduled"})
		})
		router.Post("/capability/probes", func(w http.ResponseWriter, request *http.Request) {
			group := request.Context().Value(ctxKeyAdaptivePool{}).(adapter.AdaptivePoolGroup)
			if err := group.TriggerAdaptiveCapabilityProbe(request.Context()); err != nil {
				if errors.Is(err, adapter.ErrAdaptiveCapabilityBusy) {
					render.Status(request, http.StatusConflict)
				} else {
					render.Status(request, http.StatusServiceUnavailable)
				}
				render.JSON(w, request, newError(err.Error()))
				return
			}
			render.Status(request, http.StatusOK)
			render.JSON(w, request, map[string]string{"status": "completed"})
		})
		router.Route("/services", func(router chi.Router) {
			router.Get("/", func(w http.ResponseWriter, request *http.Request) {
				group := request.Context().Value(ctxKeyAdaptivePool{}).(adapter.AdaptivePoolGroup)
				control, loaded := group.(adapter.AdaptivePoolServiceControl)
				if !loaded {
					render.Status(request, http.StatusNotImplemented)
					render.JSON(w, request, newError("adaptive service control is unavailable"))
					return
				}
				render.JSON(w, request, map[string]any{"revision": group.AdaptiveStatus().ControlRevision, "overrides": control.AdaptiveServiceOverrides()})
			})
			router.Route("/{service}", func(router chi.Router) {
				router.Put("/", updateAdaptiveServiceOverride)
				router.Delete("/", deleteAdaptiveServiceOverride)
			})
		})
	})
	return router
}

func streamAdaptivePoolEvents(writer http.ResponseWriter, request *http.Request) {
	flusher, loaded := writer.(http.Flusher)
	if !loaded {
		render.Status(request, http.StatusNotImplemented)
		render.JSON(writer, request, newError("streaming is unavailable"))
		return
	}
	group := request.Context().Value(ctxKeyAdaptivePool{}).(adapter.AdaptivePoolGroup)
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache, no-store")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(time.Second)
	heartbeat := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	defer heartbeat.Stop()
	var previous []byte
	writeStatus := func() bool {
		status := group.AdaptiveStatus()
		payload, err := json.Marshal(status)
		if err != nil || bytes.Equal(payload, previous) {
			return true
		}
		previous = append(previous[:0], payload...)
		if _, err = writer.Write([]byte("event: status\ndata: ")); err != nil {
			return false
		}
		if _, err = writer.Write(payload); err != nil {
			return false
		}
		if _, err = writer.Write([]byte("\n\n")); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !writeStatus() {
		return
	}
	for {
		select {
		case <-request.Context().Done():
			return
		case <-ticker.C:
			if !writeStatus() {
				return
			}
		case <-heartbeat.C:
			if _, err := writer.Write([]byte(": heartbeat\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

type adaptiveServiceOverrideRequest struct {
	Mode     string `json:"mode"`
	TTL      int64  `json:"ttl"`
	Revision uint64 `json:"revision"`
}

func updateAdaptiveServiceOverride(w http.ResponseWriter, request *http.Request) {
	group := request.Context().Value(ctxKeyAdaptivePool{}).(adapter.AdaptivePoolGroup)
	control, loaded := group.(adapter.AdaptivePoolServiceControl)
	if !loaded {
		render.Status(request, http.StatusNotImplemented)
		render.JSON(w, request, newError("adaptive service control is unavailable"))
		return
	}
	var body adaptiveServiceOverrideRequest
	if err := render.DecodeJSON(request.Body, &body); err != nil {
		render.Status(request, http.StatusBadRequest)
		render.JSON(w, request, ErrBadRequest)
		return
	}
	if group.AdaptiveStatus().ControlRevision != body.Revision {
		render.Status(request, http.StatusConflict)
		render.JSON(w, request, newError("adaptive control revision conflict"))
		return
	}
	serviceID := getEscapeParam(request, "service")
	if err := control.SetAdaptiveServiceOverride(serviceID, body.Mode, time.Duration(body.TTL)*time.Second, body.Revision); err != nil {
		if group.AdaptiveStatus().ControlRevision != body.Revision {
			render.Status(request, http.StatusConflict)
		} else {
			render.Status(request, http.StatusBadRequest)
		}
		render.JSON(w, request, newError(err.Error()))
		return
	}
	render.NoContent(w, request)
}

func deleteAdaptiveServiceOverride(w http.ResponseWriter, request *http.Request) {
	group := request.Context().Value(ctxKeyAdaptivePool{}).(adapter.AdaptivePoolGroup)
	control, loaded := group.(adapter.AdaptivePoolServiceControl)
	if !loaded {
		render.Status(request, http.StatusNotImplemented)
		render.JSON(w, request, newError("adaptive service control is unavailable"))
		return
	}
	revision, err := strconv.ParseUint(request.URL.Query().Get("revision"), 10, 64)
	if err != nil {
		render.Status(request, http.StatusBadRequest)
		render.JSON(w, request, ErrBadRequest)
		return
	}
	if group.AdaptiveStatus().ControlRevision != revision {
		render.Status(request, http.StatusConflict)
		render.JSON(w, request, newError("adaptive control revision conflict"))
		return
	}
	if err = control.ClearAdaptiveServiceOverride(getEscapeParam(request, "service"), revision); err != nil {
		if group.AdaptiveStatus().ControlRevision != revision {
			render.Status(request, http.StatusConflict)
		} else {
			render.Status(request, http.StatusNotFound)
		}
		render.JSON(w, request, newError(err.Error()))
		return
	}
	render.NoContent(w, request)
}

type ctxKeyAdaptivePool struct{}

func parseAdaptivePool(server *Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			name := getEscapeParam(request, "name")
			detour, loaded := server.outbound.Outbound(name)
			if !loaded {
				render.Status(request, http.StatusNotFound)
				render.JSON(w, request, ErrNotFound)
				return
			}
			group, loaded := detour.(adapter.AdaptivePoolGroup)
			if !loaded {
				render.Status(request, http.StatusBadRequest)
				render.JSON(w, request, newError("outbound is not an adaptive pool"))
				return
			}
			ctx := context.WithValue(request.Context(), ctxKeyAdaptivePool{}, group)
			next.ServeHTTP(w, request.WithContext(ctx))
		})
	}
}
