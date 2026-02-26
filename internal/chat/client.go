package chat

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// Conn is the interface for a WebSocket connection, allowing testability.
type Conn interface {
	WriteJSON(v interface{}) error
	ReadJSON(v interface{}) error
	Close() error
}

// Client manages a chat session with the Nullify AI agents.
type Client struct {
	conn           Conn
	chatID         string
	queryParams    map[string]string
	systemPrompt   string
	mu             sync.Mutex
}

// NewClient creates a new chat client with the given connection.
func NewClient(conn Conn, queryParams map[string]string, opts ...ClientOption) *Client {
	c := &Client{
		conn:        conn,
		chatID:      generateChatID(),
		queryParams: queryParams,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ClientOption configures a chat client.
type ClientOption func(*Client)

// WithChatID sets a specific chat ID (for resuming conversations).
func WithChatID(id string) ClientOption {
	return func(c *Client) {
		c.chatID = id
	}
}

// WithSystemPrompt sets an extra system prompt.
func WithSystemPrompt(prompt string) ClientOption {
	return func(c *Client) {
		c.systemPrompt = prompt
	}
}

// Send sends a message to the chat server.
func (c *Client) Send(message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	payload := Payload{
		OwnerProvider:     c.queryParams,
		ChatID:            c.chatID,
		Message:           message,
		ExtraSystemPrompt: c.systemPrompt,
	}

	return c.conn.WriteJSON(payload)
}

// ReadResponses returns a channel that streams responses from the server.
// The channel is closed when a terminal status is received or an error occurs.
func (c *Client) ReadResponses() <-chan MessageResponse {
	ch := make(chan MessageResponse, 16)

	go func() {
		defer close(ch)

		for {
			var resp MessageResponse
			if err := c.conn.ReadJSON(&resp); err != nil {
				ch <- MessageResponse{
					Status:      StatusErrored,
					MessageType: MessageTypeError,
					Message:     fmt.Sprintf("connection error: %v", err),
				}
				return
			}

			ch <- resp

			if resp.IsTerminal() {
				return
			}
		}
	}()

	return ch
}

// ChatID returns the current chat ID.
func (c *Client) ChatID() string {
	return c.chatID
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// generateChatID creates a simple unique ID for a chat session.
func generateChatID() string {
	now := time.Now().UnixMilli()
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return fmt.Sprintf("%d-%s", now, n.Text(36))
}
