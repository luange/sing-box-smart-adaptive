package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type smartReachDialOutbound struct {
	outbound.Adapter
}

func newSmartReachDialOutbound(tag string) *smartReachDialOutbound {
	return &smartReachDialOutbound{
		Adapter: outbound.NewAdapter(C.TypeDirect, tag, []string{N.NetworkTCP}, nil),
	}
}

func (o *smartReachDialOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (o *smartReachDialOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func TestSmartReachPresetAndDomainScopedSelection(t *testing.T) {
	tests, err := buildSmartReachTests([]option.SmartReachTestOptions{{Preset: "gemini"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) != 1 || tests[0].tag != "gemini" || !reachTestMatchesHost(tests[0], "gemini.google.com") {
		t.Fatalf("unexpected Gemini preset: %+v", tests)
	}
	if tests[0].url != "https://www.google.com/generate_204" {
		t.Fatalf("Gemini must follow the Google connectivity probe, got: %s", tests[0].url)
	}
	if !containsReachStatus(tests[0].acceptedStatus, http.StatusNoContent) {
		t.Fatalf("Gemini Google connectivity probe must accept HTTP 204: %+v", tests[0].acceptedStatus)
	}

	blocked := newSmartFakeOutbound("blocked-for-gemini", nil)
	reachable := newSmartFakeOutbound("reachable-for-gemini", nil)
	smart := newTestSmart(blocked, reachable)
	smart.reachTests = tests
	smart.reachResults = map[string]map[string]adapter.SmartReachCandidateStatus{
		"gemini": {
			blocked.Tag():   {Tag: blocked.Tag(), State: "blocked", Reason: "unusual traffic"},
			reachable.Tag(): {Tag: reachable.Tag(), State: "reachable", Reason: "reach test passed"},
		},
	}
	smart.reachLastRun = map[string]time.Time{"gemini": time.Now()}

	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("gemini.google.com:443"))
	if len(ranks) != 2 || ranks[0].outbound.Tag() != reachable.Tag() || !ranks[0].eligible {
		t.Fatalf("Gemini did not prefer reachable candidate: %+v", ranks)
	}
	if ranks[1].eligible || ranks[1].status.State != "service_blocked" {
		t.Fatalf("blocked Gemini candidate remained eligible: %+v", ranks[1])
	}

	normalRanks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	if !normalRanks[0].eligible || !normalRanks[1].eligible {
		t.Fatal("Gemini evidence leaked into unrelated destination")
	}
}

func TestSmartReachChatGPTPresetUsesUnauthenticatedAPI(t *testing.T) {
	tests, err := buildSmartReachTests([]option.SmartReachTestOptions{{Preset: "chatgpt"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) != 1 {
		t.Fatalf("unexpected ChatGPT preset count: %d", len(tests))
	}
	test := tests[0]
	if test.url != "https://api.openai.com/v1/models" {
		t.Fatalf("unexpected ChatGPT probe URL: %s", test.url)
	}
	if !containsReachStatus(test.acceptedStatus, http.StatusUnauthorized) {
		t.Fatal("ChatGPT preset must accept the unauthenticated API response")
	}
	if !containsReachStatus(test.blockedStatus, http.StatusForbidden) {
		t.Fatal("ChatGPT preset must classify forbidden regions as blocked")
	}
}

func TestSmartReachClaudePresetUsesUnauthenticatedAPI(t *testing.T) {
	tests, err := buildSmartReachTests([]option.SmartReachTestOptions{{Preset: "claude"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) != 1 {
		t.Fatalf("unexpected Claude preset count: %d", len(tests))
	}
	test := tests[0]
	if test.url != "https://api.anthropic.com/v1/models" {
		t.Fatalf("unexpected Claude probe URL: %s", test.url)
	}
	if test.requestHeaders["Anthropic-Version"] != "2023-06-01" {
		t.Fatalf("missing Anthropic API version header: %+v", test.requestHeaders)
	}
	if !containsReachStatus(test.acceptedStatus, http.StatusUnauthorized) {
		t.Fatal("Claude preset must accept the unauthenticated API response")
	}
	if !containsReachStatus(test.blockedStatus, http.StatusForbidden) {
		t.Fatal("Claude preset must classify forbidden regions as blocked")
	}
}

func TestSmartTemporaryOverrideBypassesServiceBlock(t *testing.T) {
	tests, err := buildSmartReachTests([]option.SmartReachTestOptions{{Preset: "gemini"}})
	if err != nil {
		t.Fatal(err)
	}
	blocked := newSmartFakeOutbound("manual-candidate", nil)
	reachable := newSmartFakeOutbound("automatic-candidate", nil)
	smart := newTestSmart(blocked, reachable)
	smart.reachTests = tests
	smart.reachResults = map[string]map[string]adapter.SmartReachCandidateStatus{
		"gemini": {
			blocked.Tag():   {Tag: blocked.Tag(), State: "blocked"},
			reachable.Tag(): {Tag: reachable.Tag(), State: "reachable"},
		},
	}
	smart.reachLastRun = map[string]time.Time{"gemini": time.Now()}
	if !smart.SelectTemporaryOutbound(blocked.Tag(), time.Minute, "manual verification") {
		t.Fatal("failed to select temporary override")
	}
	ranks, _, _, _ := smart.rank(context.Background(), N.NetworkTCP, M.ParseSocksaddr("gemini.google.com:443"))
	if ranks[0].outbound.Tag() != blocked.Tag() || !ranks[0].eligible {
		t.Fatalf("temporary override did not bypass service evidence: %+v", ranks)
	}
}

func TestSmartReachProbeClassifiesHTTPResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/reachable":
			if request.Header.Get("X-Reach-Test") != "enabled" {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte("service ready"))
		case "/blocked-status":
			response.WriteHeader(http.StatusUnavailableForLegalReasons)
		case "/blocked-body":
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write([]byte("UnUsUaL TrAfFiC detected"))
		case "/blocked-header":
			response.Header().Set("Location", "/app-unavailable-in-region")
			response.WriteHeader(http.StatusFound)
		default:
			response.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	candidate := newSmartReachDialOutbound("direct-test")
	smart := newTestSmart(candidate)
	base := smartReachTest{
		tag:            "service",
		timeout:        time.Second,
		acceptedStatus: []uint16{http.StatusOK, http.StatusFound},
		blockedStatus:  []uint16{http.StatusUnavailableForLegalReasons},
		requestHeaders: map[string]string{"X-Reach-Test": "enabled"},
		blockedBody:    []string{"unusual traffic"},
		blockedHeaders: map[string][]string{"location": {"app-unavailable-in-region"}},
		maxBodyBytes:   4096,
	}

	testCases := []struct {
		path   string
		state  string
		reason string
	}{
		{"/reachable", "reachable", "reach test passed"},
		{"/blocked-status", "blocked", "blocked HTTP status"},
		{"/blocked-body", "blocked", "blocked body marker: unusual traffic"},
		{"/blocked-header", "blocked", "blocked header: location"},
		{"/unexpected", "unreachable", "unexpected HTTP status"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.path, func(t *testing.T) {
			test := base
			test.url = server.URL + testCase.path
			status := smart.probeCandidateReach(context.Background(), test, candidate)
			if status.State != testCase.state || status.Reason != testCase.reason {
				t.Fatalf("unexpected status: %+v", status)
			}
		})
	}
}

func TestSmartReachGlobalConcurrencyIsBounded(t *testing.T) {
	var active atomic.Int64
	var maximum atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	candidate := newSmartReachDialOutbound("direct-concurrency-test")
	smart := newTestSmart(candidate)
	test := smartReachTest{
		tag:            "concurrency",
		url:            server.URL,
		timeout:        time.Second,
		acceptedStatus: []uint16{http.StatusOK},
		maxBodyBytes:   1024,
	}
	var workers sync.WaitGroup
	for range smartReachGlobalConcurrency * 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			status := smart.probeCandidateReach(context.Background(), test, candidate)
			if status.State != "reachable" {
				t.Errorf("unexpected probe state: %+v", status)
			}
		}()
	}
	workers.Wait()
	if observed := maximum.Load(); observed > smartReachGlobalConcurrency {
		t.Fatalf("global reach concurrency exceeded: %d", observed)
	}
}
