package chat

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderToolCall(t *testing.T) {
	result := RenderToolCall("calling search_findings")
	require.Contains(t, result, "[tool]")
	require.Contains(t, result, "calling search_findings")
}

func TestRenderStatus(t *testing.T) {
	result := RenderStatus("analyzing findings...")
	require.Contains(t, result, "analyzing findings...")
}

func TestRenderResponse(t *testing.T) {
	result := RenderResponse("Here are your findings")
	require.Equal(t, "Here are your findings", result)
}

func TestRenderError(t *testing.T) {
	result := RenderError("connection failed")
	require.Contains(t, result, "connection failed")
}

func TestRenderMessage(t *testing.T) {
	tests := []struct {
		name     string
		msg      MessageResponse
		contains string
	}{
		{"tool call", MessageResponse{MessageType: MessageTypeToolCall, Message: "tool"}, "[tool]"},
		{"status", MessageResponse{MessageType: MessageTypeStatusMessage, Message: "status"}, "status"},
		{"response", MessageResponse{MessageType: MessageTypeResponse, Message: "response"}, "response"},
		{"error", MessageResponse{MessageType: MessageTypeError, Message: "error"}, "error"},
		{"unknown type", MessageResponse{MessageType: "other", Message: "fallback"}, "fallback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RenderMessage(tt.msg)
			require.Contains(t, result, tt.contains)
		})
	}
}
