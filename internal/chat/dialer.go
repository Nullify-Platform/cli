package chat

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
)

// Dial connects to the Nullify chat WebSocket.
func Dial(ctx context.Context, host string, token string) (Conn, error) {
	url := fmt.Sprintf("wss://%s/chat/websocket", host)

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	dialer := websocket.DefaultDialer
	conn, _, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to chat: %w", err)
	}

	return conn, nil
}
