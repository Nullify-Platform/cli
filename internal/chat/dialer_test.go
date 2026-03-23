package chat

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestBuildWebSocketURL(t *testing.T) {
	require.Equal(t, "wss://api.acme.nullify.ai/chat/websocket", buildWebSocketURL("acme.nullify.ai"))
	require.Equal(t, "wss://api.acme.nullify.ai/chat/websocket", buildWebSocketURL("api.acme.nullify.ai"))
}

func TestFormatDialErrorWithForbiddenHandshake(t *testing.T) {
	err := formatDialError(
		"wss://api.acme.nullify.ai/chat/websocket",
		websocket.ErrBadHandshake,
		&http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(strings.NewReader(`{"message":"User is not authorized"}`)),
		},
	)

	require.EqualError(t, err, "failed to connect to chat at wss://api.acme.nullify.ai/chat/websocket: websocket handshake failed with HTTP 403 Forbidden: User is not authorized. The chat websocket is reachable, but this identity is not allowed to use it. Verify chat permissions for this host.")
}

func TestFormatDialErrorWithoutResponse(t *testing.T) {
	err := formatDialError("wss://api.acme.nullify.ai/chat/websocket", errors.New("tls: internal error"), nil)
	require.EqualError(t, err, "failed to connect to chat at wss://api.acme.nullify.ai/chat/websocket: tls: internal error")
}

func TestSummarizeHandshakeBodyReturnsRawBody(t *testing.T) {
	message := summarizeHandshakeBody(strings.NewReader("plain text failure"))
	require.Equal(t, "plain text failure", message)
}
