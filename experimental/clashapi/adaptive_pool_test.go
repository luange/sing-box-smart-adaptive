package clashapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type clashCapabilityGroup struct {
	adapter.AdaptivePoolGroup
	err   error
	calls int
}

func (g *clashCapabilityGroup) AdaptiveStatus() adapter.AdaptivePoolStatus {
	return adapter.AdaptivePoolStatus{Generation: 9, CandidateCount: 2, ControlRevision: 4, Mode: "adaptive"}
}

func (g *clashCapabilityGroup) TriggerAdaptiveCapabilityProbe(context.Context) error {
	g.calls++
	return g.err
}

func TestAdaptivePoolEventStreamStartsWithStatus(t *testing.T) {
	group := &clashCapabilityGroup{}
	server := &Server{outbound: &clashCapabilityOutboundManager{group: group}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/pool/events", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	adaptivePoolRouter(server).ServeHTTP(response, request)
	if contentType := response.Header().Get("Content-Type"); contentType != "text/event-stream" {
		t.Fatalf("unexpected content type: %q", contentType)
	}
	body := response.Body.String()
	if !strings.Contains(body, "event: status") || !strings.Contains(body, `"generation":9`) || strings.Contains(body, "token=") {
		t.Fatalf("unexpected event payload: %s", body)
	}
}

type clashCapabilityOutboundManager struct {
	adapter.OutboundManager
	group adapter.Outbound
}

func (m *clashCapabilityOutboundManager) Outbound(name string) (adapter.Outbound, bool) {
	return m.group, name == "pool"
}

func TestAdaptivePoolCapabilityProbeRoute(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "completed", status: http.StatusOK},
		{name: "busy", err: adapter.ErrAdaptiveCapabilityBusy, status: http.StatusConflict},
		{name: "disabled", err: adapter.ErrAdaptiveCapabilityUnavailable, status: http.StatusServiceUnavailable},
		{name: "failure", err: errors.New("capability cycle failed"), status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			group := &clashCapabilityGroup{err: test.err}
			server := &Server{outbound: &clashCapabilityOutboundManager{group: group}}
			request := httptest.NewRequest(http.MethodPost, "/pool/capability/probes", nil)
			response := httptest.NewRecorder()
			adaptivePoolRouter(server).ServeHTTP(response, request)
			if response.Code != test.status || group.calls != 1 {
				t.Fatalf("unexpected capability route result: status=%d calls=%d body=%s", response.Code, group.calls, response.Body.String())
			}
		})
	}
}
