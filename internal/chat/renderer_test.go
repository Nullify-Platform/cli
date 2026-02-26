package chat

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderToolCall(t *testing.T) {
	result := RenderToolCall("calling search_findings")
	require.Contains(t, result, "[tool]")
	require.Contains(t, result, "calling search_findings")
	require.True(t, strings.HasSuffix(result, ansiReset))
}

func TestRenderStatus(t *testing.T) {
	result := RenderStatus("analyzing findings...")
	require.Contains(t, result, "analyzing findings...")
	require.True(t, strings.HasSuffix(result, ansiReset))
}

func TestRenderResponse(t *testing.T) {
	result := RenderResponse("Here are your findings")
	require.Equal(t, "Here are your findings", result)
}

func TestRenderError(t *testing.T) {
	result := RenderError("connection failed")
	require.Contains(t, result, "connection failed")
	require.True(t, strings.HasSuffix(result, ansiReset))
}

func TestRenderMessage(t *testing.T) {
	tests := []struct {
		msg      MessageResponse
		contains string
	}{
		{MessageResponse{MessageType: MessageTypeToolCall, Message: "tool"}, "[tool]"},
		{MessageResponse{MessageType: MessageTypeStatusMessage, Message: "status"}, "status"},
		{MessageResponse{MessageType: MessageTypeResponse, Message: "response"}, "response"},
		{MessageResponse{MessageType: MessageTypeError, Message: "error"}, "error"},
	}

	for _, tt := range tests {
		result := RenderMessage(tt.msg)
		require.Contains(t, result, tt.contains)
	}
}
