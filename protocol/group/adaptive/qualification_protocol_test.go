package adaptive

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestValidateOpenAIResponsesQualificationStream(t *testing.T) {
	stream := "event: response.created\ndata: {\"type\":\"response.created\"}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"secret-output\"}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"secret-id\"}}\n\n"
	verdict := ValidateQualificationProtocolStream(QualificationProtocolOpenAIResponsesSSE, strings.NewReader(stream))
	if verdict.Outcome != QualificationProtocolEligible || !verdict.FirstEvent || !verdict.TerminalEvent || verdict.FailureClass != "" {
		t.Fatalf("unexpected OpenAI verdict: %+v", verdict)
	}
	if strings.Contains(verdict.FailureClass, "secret") {
		t.Fatalf("OpenAI payload leaked through verdict: %+v", verdict)
	}
}

func TestValidateAnthropicMessagesQualificationStream(t *testing.T) {
	stream := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"secret-output\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	verdict := ValidateQualificationProtocolStream(QualificationProtocolAnthropicMessagesSSE, strings.NewReader(stream))
	if verdict.Outcome != QualificationProtocolEligible || !verdict.TerminalEvent {
		t.Fatalf("unexpected Anthropic verdict: %+v", verdict)
	}
}

func TestValidateGeminiGenerateQualificationStream(t *testing.T) {
	stream := "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"secret-output\"}]}}]}\n\n" +
		"data: {\"candidates\":[{\"finishReason\":\"STOP\"}]}\n\n"
	verdict := ValidateQualificationProtocolStream(QualificationProtocolGeminiGenerateSSE, strings.NewReader(stream))
	if verdict.Outcome != QualificationProtocolEligible || !verdict.TerminalEvent {
		t.Fatalf("unexpected Gemini verdict: %+v", verdict)
	}
}

func TestQualificationProtocolFailureClassesAreStructured(t *testing.T) {
	tests := []struct {
		name     string
		protocol QualificationProtocol
		stream   string
		outcome  QualificationProtocolOutcome
		class    string
	}{
		{name: "openai provider error", protocol: QualificationProtocolOpenAIResponsesSSE, stream: "data: {\"type\":\"response.failed\",\"error\":{\"message\":\"secret-token\"}}\n", outcome: QualificationProtocolBlocked, class: "provider_error"},
		{name: "anthropic missing terminal", protocol: QualificationProtocolAnthropicMessagesSSE, stream: "data: {\"type\":\"message_start\"}\n", outcome: QualificationProtocolTransient, class: "missing_terminal"},
		{name: "gemini invalid", protocol: QualificationProtocolGeminiGenerateSSE, stream: "data: {\"unexpected\":\"secret-token\"}\n", outcome: QualificationProtocolInvalid, class: "invalid_event"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verdict := ValidateQualificationProtocolStream(test.protocol, strings.NewReader(test.stream))
			if verdict.Outcome != test.outcome || verdict.FailureClass != test.class {
				t.Fatalf("unexpected verdict: %+v", verdict)
			}
			if strings.Contains(verdict.FailureClass, "secret") {
				t.Fatalf("payload leaked through verdict: %+v", verdict)
			}
		})
	}
}

func TestQualificationProtocolRejectsOversizedEventWithoutEcho(t *testing.T) {
	stream := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + strings.Repeat("secret-token", qualificationProtocolMaxLine) + "\"}\n"
	verdict := ValidateQualificationProtocolStream(QualificationProtocolOpenAIResponsesSSE, strings.NewReader(stream))
	if verdict.Outcome != QualificationProtocolInvalid || verdict.FailureClass != "stream_limit" {
		t.Fatalf("oversized event was not rejected structurally: %+v", verdict)
	}
	if strings.Contains(verdict.FailureClass, "secret") {
		t.Fatalf("oversized payload leaked through verdict: %+v", verdict)
	}
}

func TestQualificationProtocolConsumerUsesObservationPipeline(t *testing.T) {
	manager := NewRuntimeManager()
	pool := preparedLifecyclePool(t, manager, "qualification-consumer")
	pool.ctx = context.Background()
	pool.qualificationEnabled = true
	pool.observationIngestor = NewObservationIngestor(nil, nil, time.Minute, 128)
	if err := pool.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	pool.OnRuntimeEpochPublishCommit()
	defer pool.Close()

	stream := "data: {\"type\":\"response.created\"}\n\ndata: {\"type\":\"response.completed\"}\n"
	verdict, err := pool.IngestQualificationProtocolStream("chatgpt_web", "node", QualificationProtocolOpenAIResponsesSSE, strings.NewReader(stream))
	if err != nil || verdict.Outcome != QualificationProtocolEligible {
		t.Fatalf("qualification stream was not ingested: verdict=%+v err=%v", verdict, err)
	}
	snapshot := pool.catalog.Snapshot()
	service := pool.health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", "chatgpt_web")
	if service.Health != HealthHealthy || service.Successes != 1 {
		t.Fatalf("qualification evidence did not reach service health: %+v", service)
	}
	endpoint := pool.health.EndpointHandle(snapshot.Candidates[0].Handle)
	if endpoint.Successes != 0 || endpoint.Failures != 0 {
		t.Fatalf("qualification evidence polluted endpoint health: %+v", endpoint)
	}

	transient := "data: {\"type\":\"response.created\"}\n"
	verdict, err = pool.IngestQualificationProtocolStream("chatgpt_web", "node", QualificationProtocolOpenAIResponsesSSE, strings.NewReader(transient))
	if err != nil || verdict.Outcome != QualificationProtocolTransient {
		t.Fatalf("transient stream was not isolated: verdict=%+v err=%v", verdict, err)
	}
	serviceAfter := pool.health.StatusHandle(snapshot.Candidates[0].Handle, DomainService, "", "chatgpt_web")
	if serviceAfter.Successes != service.Successes || serviceAfter.Failures != service.Failures {
		t.Fatalf("transient stream mutated service health: before=%+v after=%+v", service, serviceAfter)
	}
}

func TestQualificationProtocolKeepsIPv4AndIPv6Independent(t *testing.T) {
	manager := NewRuntimeManager()
	pool := preparedLifecyclePool(t, manager, "qualification-family")
	pool.ctx = context.Background()
	pool.qualificationEnabled = true
	pool.observationIngestor = NewObservationIngestor(nil, nil, time.Minute, 128)
	if err := pool.OnRuntimeEpochPublish(); err != nil {
		t.Fatal(err)
	}
	pool.OnRuntimeEpochPublishCommit()
	defer pool.Close()

	eligible := "data: {\"type\":\"response.created\"}\n\ndata: {\"type\":\"response.completed\"}\n"
	blocked := "data: {\"type\":\"response.failed\",\"error\":{\"message\":\"redacted\"}}\n"
	if _, err := pool.IngestQualificationProtocolStreamForPath("chatgpt_web", "node", "tcp/ipv4", QualificationProtocolOpenAIResponsesSSE, strings.NewReader(eligible)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.IngestQualificationProtocolStreamForPath("chatgpt_web", "node", "tcp/ipv6", QualificationProtocolOpenAIResponsesSSE, strings.NewReader(blocked)); err != nil {
		t.Fatal(err)
	}
	handle := pool.catalog.Snapshot().Candidates[0].Handle
	v4 := pool.health.StatusHandle(handle, DomainService, "tcp/ipv4", "chatgpt_web")
	v6 := pool.health.StatusHandle(handle, DomainService, "tcp/ipv6", "chatgpt_web")
	if v4.Health != HealthHealthy || v4.Successes != 1 || v4.Failures != 0 {
		t.Fatalf("IPv4 qualification was polluted: %+v", v4)
	}
	if v6.Health != HealthDegraded || v6.Successes != 0 || v6.Failures != 1 {
		t.Fatalf("IPv6 qualification was not isolated: %+v", v6)
	}
	engine := NewPolicyEngine(pool.health, 3, "fallback")
	candidate := pool.catalog.Snapshot().Candidates[0]
	v4Score := engine.candidateScore(candidate, ServiceContext{ID: "chatgpt_web", Transport: "tcp", HealthTransport: "tcp/ipv4"})
	v6Score := engine.candidateScore(candidate, ServiceContext{ID: "chatgpt_web", Transport: "tcp", HealthTransport: "tcp/ipv6"})
	if v6Score.HealthPriority <= v4Score.HealthPriority || v6Score.DominantEvidence != "service:chatgpt_web/tcp/ipv6" {
		t.Fatalf("policy did not isolate the blocked IPv6 family: ipv4=%+v ipv6=%+v", v4Score, v6Score)
	}
}
