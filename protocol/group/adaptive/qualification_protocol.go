package adaptive

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

type QualificationProtocol string

const (
	QualificationProtocolOpenAIResponsesSSE   QualificationProtocol = "openai_responses_sse"
	QualificationProtocolAnthropicMessagesSSE QualificationProtocol = "anthropic_messages_sse"
	QualificationProtocolGeminiGenerateSSE    QualificationProtocol = "gemini_generate_sse"
)

type QualificationProtocolOutcome string

const (
	QualificationProtocolEligible  QualificationProtocolOutcome = "eligible"
	QualificationProtocolBlocked   QualificationProtocolOutcome = "blocked"
	QualificationProtocolTransient QualificationProtocolOutcome = "transient"
	QualificationProtocolInvalid   QualificationProtocolOutcome = "invalid"
)

type QualificationProtocolVerdict struct {
	Outcome       QualificationProtocolOutcome
	FirstEvent    bool
	TerminalEvent bool
	FailureClass  string
}

const qualificationProtocolMaxLine = 1024 * 1024

// ValidateQualificationProtocolStream validates only provider protocol
// structure. It deliberately returns no payload, model output, request ID or
// upstream error text, so callers cannot accidentally persist sensitive data.
func ValidateQualificationProtocolStream(protocol QualificationProtocol, reader io.Reader) QualificationProtocolVerdict {
	if reader == nil {
		return qualificationProtocolFailure(QualificationProtocolInvalid, "empty_stream")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), qualificationProtocolMaxLine)
	eventName := ""
	verdict := QualificationProtocolVerdict{Outcome: QualificationProtocolTransient}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		verdict.FirstEvent = true
		var terminal, eligible bool
		var failure string
		switch protocol {
		case QualificationProtocolOpenAIResponsesSSE:
			terminal, eligible, failure = validateOpenAIQualificationEvent(payload)
		case QualificationProtocolAnthropicMessagesSSE:
			terminal, eligible, failure = validateAnthropicQualificationEvent(eventName, payload)
		case QualificationProtocolGeminiGenerateSSE:
			terminal, eligible, failure = validateGeminiQualificationEvent(payload)
		default:
			return qualificationProtocolFailure(QualificationProtocolInvalid, "unknown_protocol")
		}
		if failure != "" {
			verdict.Outcome = QualificationProtocolInvalid
			if failure == "provider_error" {
				verdict.Outcome = QualificationProtocolBlocked
			}
			verdict.FailureClass = failure
			return verdict
		}
		if terminal {
			verdict.TerminalEvent = true
			if eligible {
				verdict.Outcome = QualificationProtocolEligible
			} else {
				verdict.Outcome = QualificationProtocolTransient
				verdict.FailureClass = "incomplete"
			}
			return verdict
		}
	}
	if scanner.Err() != nil {
		return qualificationProtocolFailure(QualificationProtocolInvalid, "stream_limit")
	}
	if !verdict.FirstEvent {
		verdict.FailureClass = "empty_stream"
	} else {
		verdict.FailureClass = "missing_terminal"
	}
	return verdict
}

func validateOpenAIQualificationEvent(payload string) (terminal, eligible bool, failure string) {
	var event struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(payload), &event) != nil || event.Type == "" {
		return false, false, "invalid_event"
	}
	switch event.Type {
	case "response.completed":
		return true, true, ""
	case "response.incomplete":
		return true, false, ""
	case "response.failed", "response.cancelled", "response.canceled", "error":
		return true, false, "provider_error"
	default:
		return false, false, ""
	}
}

func validateAnthropicQualificationEvent(eventName, payload string) (terminal, eligible bool, failure string) {
	var event struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(payload), &event) != nil {
		return false, false, "invalid_event"
	}
	eventType := event.Type
	if eventType == "" {
		eventType = eventName
	}
	switch eventType {
	case "message_stop":
		return true, true, ""
	case "error":
		return true, false, "provider_error"
	case "message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "ping":
		return false, false, ""
	default:
		return false, false, "invalid_event"
	}
}

func validateGeminiQualificationEvent(payload string) (terminal, eligible bool, failure string) {
	var event struct {
		Error      json.RawMessage `json:"error"`
		Candidates []struct {
			FinishReason string          `json:"finishReason"`
			Content      json.RawMessage `json:"content"`
		} `json:"candidates"`
	}
	if json.Unmarshal([]byte(payload), &event) != nil {
		return false, false, "invalid_event"
	}
	if len(event.Error) > 0 && string(event.Error) != "null" {
		return true, false, "provider_error"
	}
	if len(event.Candidates) == 0 {
		return false, false, "invalid_event"
	}
	for _, candidate := range event.Candidates {
		if candidate.FinishReason != "" {
			return true, true, ""
		}
		if len(candidate.Content) > 0 && string(candidate.Content) != "null" {
			return false, false, ""
		}
	}
	return false, false, "invalid_event"
}

func qualificationProtocolFailure(outcome QualificationProtocolOutcome, class string) QualificationProtocolVerdict {
	return QualificationProtocolVerdict{Outcome: outcome, FailureClass: class}
}
