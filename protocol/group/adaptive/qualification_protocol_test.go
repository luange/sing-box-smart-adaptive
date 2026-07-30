package adaptive

import (
	"strings"
	"testing"
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
