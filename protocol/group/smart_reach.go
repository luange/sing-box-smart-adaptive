package group

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group/probe"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	smartReachStatusLimit       = 32
	smartReachGlobalConcurrency = 8
)

var smartReachProbeSlots = make(chan struct{}, smartReachGlobalConcurrency)

type smartReachTest struct {
	tag              string
	preset           string
	domains          []string
	url              string
	interval         time.Duration
	timeout          time.Duration
	acceptedStatus   []uint16
	blockedStatus    []uint16
	requestHeaders   map[string]string
	reachableBody    []string
	blockedBody      []string
	blockedHeaders   map[string][]string
	unmeasuredPolicy string
	maxBodyBytes     int64
}

func buildSmartReachTests(options []option.SmartReachTestOptions) ([]smartReachTest, error) {
	tests := make([]smartReachTest, 0, len(options))
	seen := make(map[string]bool)
	for index, raw := range options {
		normalized, err := normalizeSmartReachTest(raw)
		if err != nil {
			return nil, E.Cause(err, "reach_tests[", index, "]")
		}
		if seen[normalized.tag] {
			return nil, E.New("duplicate reach test tag: ", normalized.tag)
		}
		seen[normalized.tag] = true
		tests = append(tests, normalized)
	}
	return tests, nil
}

func normalizeSmartReachTest(raw option.SmartReachTestOptions) (smartReachTest, error) {
	preset := strings.ToLower(strings.TrimSpace(raw.Preset))
	if raw.Tag == "" {
		raw.Tag = preset
	}
	switch preset {
	case "":
	case "gemini":
		// Gemini follows the Google connectivity signal. Probing the Gemini web
		// application directly is unstable (redirects, bot challenges and
		// application-layer policy can all produce false negatives) and must not
		// become a hard node-selection gate.
		setReachDefaults(&raw, probe.GoogleConnectivityURL, []string{"gemini.google.com", "aistudio.google.com"}, []uint16{204}, []uint16{403, 429, 451}, []string{"unusual traffic"}, nil)
	case "chatgpt":
		setReachDefaults(&raw, "https://api.openai.com/v1/models", []string{"chatgpt.com", "openai.com"}, []uint16{401}, []uint16{403, 429, 451}, []string{"unsupported_country", "unsupported country", "not available in your country"}, nil)
	case "claude":
		setReachDefaults(&raw, "https://api.anthropic.com/v1/models", []string{"claude.ai", "anthropic.com"}, []uint16{401}, []uint16{403, 429, 451}, []string{"unsupported_country", "unsupported country", "not available in your region"}, nil)
		if len(raw.RequestHeaders) == 0 {
			raw.RequestHeaders = map[string]string{"anthropic-version": "2023-06-01"}
		}
	case "git-ssh":
		setReachDefaults(&raw, "https://github.com/", []string{"github.com"}, []uint16{200, 301, 302}, nil, nil, nil)
	default:
		return smartReachTest{}, E.New("unknown reach test preset: ", raw.Preset)
	}
	if raw.Tag == "" {
		return smartReachTest{}, E.New("missing tag")
	}
	if raw.URL == "" {
		return smartReachTest{}, E.New("missing url")
	}
	parsedURL, err := url.Parse(raw.URL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return smartReachTest{}, E.New("invalid HTTP URL: ", raw.URL)
	}
	interval := time.Duration(raw.Interval)
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	timeout := time.Duration(raw.Timeout)
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	policy := strings.ToLower(raw.UnmeasuredPolicy)
	if policy == "" {
		policy = "fallback"
	}
	switch policy {
	case "allow", "fallback", "suspend", "reject":
	default:
		return smartReachTest{}, E.New("unknown unmeasured_policy: ", raw.UnmeasuredPolicy)
	}
	maxBodyBytes := raw.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = 128 * 1024
	}
	maxBodyBytes = min(maxBodyBytes, 1024*1024)
	return smartReachTest{
		tag:              raw.Tag,
		preset:           preset,
		domains:          normalizeReachStrings(raw.Domains),
		url:              raw.URL,
		interval:         interval,
		timeout:          timeout,
		acceptedStatus:   raw.AcceptedStatus,
		blockedStatus:    raw.BlockedStatus,
		requestHeaders:   normalizeReachRequestHeaders(raw.RequestHeaders),
		reachableBody:    normalizeReachStrings(raw.ReachableBody),
		blockedBody:      normalizeReachStrings(raw.BlockedBody),
		blockedHeaders:   normalizeReachHeaders(raw.BlockedHeaders),
		unmeasuredPolicy: policy,
		maxBodyBytes:     maxBodyBytes,
	}, nil
}

func normalizeReachRequestHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers))
	for name, value := range headers {
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name != "" && value != "" {
			result[name] = value
		}
	}
	return result
}

func setReachDefaults(raw *option.SmartReachTestOptions, probeURL string, domains []string, accepted, blocked []uint16, blockedBody []string, blockedHeaders map[string][]string) {
	if raw.URL == "" {
		raw.URL = probeURL
	}
	if len(raw.Domains) == 0 {
		raw.Domains = domains
	}
	if len(raw.AcceptedStatus) == 0 {
		raw.AcceptedStatus = accepted
	}
	if len(raw.BlockedStatus) == 0 {
		raw.BlockedStatus = blocked
	}
	if len(raw.BlockedBody) == 0 {
		raw.BlockedBody = blockedBody
	}
	if len(raw.BlockedHeaders) == 0 {
		raw.BlockedHeaders = blockedHeaders
	}
}

func normalizeReachStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.TrimPrefix(value, ".")
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func normalizeReachHeaders(headers map[string][]string) map[string][]string {
	result := make(map[string][]string, len(headers))
	for name, values := range headers {
		result[strings.ToLower(name)] = normalizeReachStrings(values)
	}
	return result
}

func (s *Smart) runDueReachTests(ctx context.Context, force bool) {
	if len(s.reachTests) == 0 {
		return
	}
	now := time.Now()
	for _, test := range s.reachTests {
		s.reachAccess.RLock()
		lastRun := s.reachLastRun[test.tag]
		s.reachAccess.RUnlock()
		if !force && now.Sub(lastRun) < test.interval {
			continue
		}
		s.runReachTest(ctx, test)
	}
}

func (s *Smart) runReachTest(ctx context.Context, test smartReachTest) {
	s.access.RLock()
	candidates := append([]adapter.Outbound(nil), s.candidates...)
	s.access.RUnlock()
	results := make(map[string]adapter.SmartReachCandidateStatus, len(candidates))
	type result struct {
		tag    string
		status adapter.SmartReachCandidateStatus
	}
	jobs := make(chan adapter.Outbound)
	resultChannel := make(chan result, len(candidates))
	workerCount := min(5, len(candidates))
	for range workerCount {
		go func() {
			for candidate := range jobs {
				resultChannel <- result{candidate.Tag(), s.probeCandidateReach(ctx, test, candidate)}
			}
		}()
	}
	for _, candidate := range candidates {
		if commonCandidateSupportsTCP(candidate) {
			jobs <- candidate
		}
	}
	close(jobs)
	for range countTCPReachCandidates(candidates) {
		item := <-resultChannel
		results[item.tag] = item.status
	}
	checkedAt := time.Now()
	s.reachAccess.Lock()
	s.reachResults[test.tag] = results
	s.reachLastRun[test.tag] = checkedAt
	s.reachAccess.Unlock()
}

func commonCandidateSupportsTCP(candidate adapter.Outbound) bool {
	for _, network := range candidate.Network() {
		if network == N.NetworkTCP {
			return true
		}
	}
	return false
}

func countTCPReachCandidates(candidates []adapter.Outbound) int {
	count := 0
	for _, candidate := range candidates {
		if commonCandidateSupportsTCP(candidate) {
			count++
		}
	}
	return count
}

func (s *Smart) probeCandidateReach(parent context.Context, test smartReachTest, candidate adapter.Outbound) adapter.SmartReachCandidateStatus {
	checkedAt := time.Now()
	status := adapter.SmartReachCandidateStatus{Tag: candidate.Tag(), State: "unreachable", CheckedAt: checkedAt}
	select {
	case smartReachProbeSlots <- struct{}{}:
		defer func() { <-smartReachProbeSlots }()
	case <-parent.Done():
		status.Reason = parent.Err().Error()
		return status
	}
	probeCtx, cancel := context.WithTimeout(parent, test.timeout)
	defer cancel()
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return candidate.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, test.url, nil)
	if err != nil {
		status.Reason = err.Error()
		return status
	}
	for name, value := range test.requestHeaders {
		request.Header.Set(name, value)
	}
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sing-box Smart Reach-Test)")
	}
	response, err := client.Do(request)
	if err != nil {
		status.Reason = err.Error()
		return status
	}
	defer response.Body.Close()
	status.HTTPStatus = response.StatusCode
	body, readErr := io.ReadAll(io.LimitReader(response.Body, test.maxBodyBytes))
	if readErr != nil {
		status.Reason = readErr.Error()
		return status
	}
	bodyText := strings.ToLower(string(body))
	if containsReachStatus(test.blockedStatus, response.StatusCode) {
		status.State = "blocked"
		status.Reason = "blocked HTTP status"
		return status
	}
	for _, marker := range test.blockedBody {
		if strings.Contains(bodyText, marker) {
			status.State = "blocked"
			status.Reason = "blocked body marker: " + marker
			return status
		}
	}
	for header, markers := range test.blockedHeaders {
		headerValue := strings.ToLower(response.Header.Get(header))
		for _, marker := range markers {
			if strings.Contains(headerValue, marker) {
				status.State = "blocked"
				status.Reason = "blocked header: " + header
				return status
			}
		}
	}
	if len(test.acceptedStatus) > 0 && !containsReachStatus(test.acceptedStatus, response.StatusCode) {
		status.Reason = "unexpected HTTP status"
		return status
	}
	if len(test.reachableBody) > 0 {
		matched := false
		for _, marker := range test.reachableBody {
			if strings.Contains(bodyText, marker) {
				matched = true
				break
			}
		}
		if !matched {
			status.Reason = "reachable body marker missing"
			return status
		}
	}
	status.State = "reachable"
	status.Reason = "reach test passed"
	return status
}

func containsReachStatus(values []uint16, status int) bool {
	for _, value := range values {
		if int(value) == status {
			return true
		}
	}
	return false
}

func (s *Smart) applyReachTestEvidence(metadata *adapter.InboundContext, destination M.Socksaddr, ranks []smartRank) {
	host := smartDestinationHost(metadata, destination)
	if host == "" {
		return
	}
	for _, test := range s.reachTests {
		if !reachTestMatchesHost(test, host) {
			continue
		}
		s.reachAccess.RLock()
		results := s.reachResults[test.tag]
		s.reachAccess.RUnlock()
		reachableCount := 0
		for _, rank := range ranks {
			if results[rank.outbound.Tag()].State == "reachable" {
				reachableCount++
			}
		}
		for index := range ranks {
			result, measured := results[ranks[index].outbound.Tag()]
			switch {
			case measured && result.State == "reachable":
			case measured && result.State == "blocked":
				ranks[index].eligible = false
				ranks[index].status.State = "service_blocked"
				ranks[index].status.Reason = test.tag + ": " + result.Reason
			case measured && result.State == "unreachable":
				ranks[index].eligible = false
				ranks[index].status.State = "service_unreachable"
				ranks[index].status.Reason = test.tag + ": " + result.Reason
			case !measured:
				switch test.unmeasuredPolicy {
				case "allow":
				case "fallback":
					if reachableCount > 0 {
						ranks[index].eligible = false
						ranks[index].status.State = "service_unmeasured"
						ranks[index].status.Reason = test.tag + ": not measured"
					}
				case "suspend", "reject":
					ranks[index].eligible = false
					ranks[index].status.State = "service_unmeasured"
					ranks[index].status.Reason = test.tag + ": not measured"
				}
			}
		}
	}
}

func reachTestMatchesHost(test smartReachTest, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range test.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func smartDestinationHost(metadata *adapter.InboundContext, destination M.Socksaddr) string {
	if metadata != nil {
		if metadata.Domain != "" {
			return metadata.Domain
		}
	}
	if destination.IsDomain() {
		return destination.Fqdn
	}
	return ""
}

func (s *Smart) reachTestStatus() []adapter.SmartReachTestStatus {
	if len(s.reachTests) == 0 {
		return nil
	}
	statuses := make([]adapter.SmartReachTestStatus, 0, len(s.reachTests))
	s.access.RLock()
	candidateCount := len(s.candidates)
	s.access.RUnlock()
	s.reachAccess.RLock()
	defer s.reachAccess.RUnlock()
	for _, test := range s.reachTests {
		results := s.reachResults[test.tag]
		stateCounts := map[string]int{"unmeasured": 0}
		details := make([]adapter.SmartReachCandidateStatus, 0, min(len(results), smartReachStatusLimit))
		for _, result := range results {
			stateCounts[result.State]++
			if len(details) < smartReachStatusLimit {
				details = append(details, result)
			}
		}
		stateCounts["unmeasured"] = max(0, candidateCount-len(results))
		statuses = append(statuses, adapter.SmartReachTestStatus{
			Tag:                       test.tag,
			Preset:                    test.preset,
			Domains:                   append([]string(nil), test.domains...),
			URL:                       test.url,
			CheckedAt:                 s.reachLastRun[test.tag],
			StateCounts:               stateCounts,
			CandidateCount:            candidateCount,
			CandidateDetailsCount:     len(details),
			CandidateDetailsTruncated: len(details) < candidateCount,
			Candidates:                details,
		})
	}
	return statuses
}
