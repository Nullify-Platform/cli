package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

// Dial connects to the Nullify chat WebSocket.
func Dial(ctx context.Context, host string, token string) (Conn, error) {
	url := buildWebSocketURL(host)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	dialer := websocket.DefaultDialer
	conn, resp, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		return nil, formatDialError(url, err, resp)
	}

	return conn, nil
}

func buildWebSocketURL(host string) string {
	return fmt.Sprintf("wss://%s/chat/websocket", websocketHost(host))
}

func websocketHost(host string) string {
	if strings.HasPrefix(host, "api.") {
		return host
	}
	return "api." + host
}

func formatDialError(url string, err error, resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("failed to connect to chat at %s: %w", url, err)
	}

	defer resp.Body.Close()

	message := summarizeHandshakeBody(resp.Body)
	base := fmt.Sprintf("failed to connect to chat at %s: websocket handshake failed with HTTP %d %s", url, resp.StatusCode, http.StatusText(resp.StatusCode))
	if message != "" {
		base += ": " + message
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		base += ". Check that your Nullify token is valid for this host."
	case http.StatusForbidden:
		base += ". The chat websocket is reachable, but this identity is not allowed to use it. Verify chat permissions for this host."
	}

	return errors.New(base)
}

func summarizeHandshakeBody(body io.Reader) string {
	if body == nil {
		return ""
	}

	data, err := io.ReadAll(io.LimitReader(body, 4096))
	if err != nil {
		return ""
	}

	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return ""
	}

	var parsed map[string]any
	if json.Unmarshal(data, &parsed) == nil {
		for _, key := range []string{"message", "error", "detail"} {
			if value, ok := parsed[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}

	return raw
}
