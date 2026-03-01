package chat

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockConn is a test implementation of the Conn interface.
type mockConn struct {
	written []any
	toRead  []MessageResponse
	readIdx int
	closed  bool
}

func (m *mockConn) WriteJSON(v any) error {
	m.written = append(m.written, v)
	return nil
}

func (m *mockConn) ReadJSON(v any) error {
	if m.readIdx >= len(m.toRead) {
		return errors.New("connection closed")
	}
	resp := m.toRead[m.readIdx]
	m.readIdx++

	// Marshal and unmarshal to simulate real JSON round-trip
	data, _ := json.Marshal(resp)
	return json.Unmarshal(data, v)
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func TestClientSend(t *testing.T) {
	conn := &mockConn{}
	c := NewClient(conn, map[string]string{"orgId": "test-org"})

	err := c.Send("hello")
	require.NoError(t, err)
	require.Len(t, conn.written, 1)

	payload := conn.written[0].(Payload)
	require.Equal(t, "hello", payload.Message)
	require.Equal(t, c.ChatID(), payload.ChatID)
	require.Equal(t, "test-org", payload.OwnerProvider["orgId"])
}

func TestClientReadResponses(t *testing.T) {
	conn := &mockConn{
		toRead: []MessageResponse{
			{Status: StatusInProgress, MessageType: MessageTypeStatusMessage, Message: "thinking..."},
			{Status: StatusInProgress, MessageType: MessageTypeResponse, Message: "hello back"},
			{Status: StatusFinished, MessageType: MessageTypeResponse, Message: "done"},
		},
	}

	c := NewClient(conn, nil)
	responses := c.ReadResponses()

	var received []MessageResponse
	for resp := range responses {
		received = append(received, resp)
	}

	require.Len(t, received, 3)
	require.Equal(t, "thinking...", received[0].Message)
	require.Equal(t, "hello back", received[1].Message)
	require.Equal(t, "done", received[2].Message)
}

func TestClientReadResponsesConnectionError(t *testing.T) {
	// When there are no messages to read, ReadJSON returns an error,
	// and ReadResponses should emit an error response and close the channel.
	conn := &mockConn{toRead: nil}
	c := NewClient(conn, nil)
	responses := c.ReadResponses()

	var received []MessageResponse
	for resp := range responses {
		received = append(received, resp)
	}

	require.Len(t, received, 1)
	require.Equal(t, StatusErrored, received[0].Status)
	require.Contains(t, received[0].Message, "connection")
}

func TestClientWithOptions(t *testing.T) {
	conn := &mockConn{}
	c := NewClient(conn, nil,
		WithChatID("custom-id"),
		WithSystemPrompt("be helpful"),
	)

	require.Equal(t, "custom-id", c.ChatID())

	err := c.Send("test")
	require.NoError(t, err)

	payload := conn.written[0].(Payload)
	require.Equal(t, "custom-id", payload.ChatID)
	require.Equal(t, "be helpful", payload.ExtraSystemPrompt)
}

func TestMessageResponseIsTerminal(t *testing.T) {
	require.True(t, (&MessageResponse{Status: StatusFinished}).IsTerminal())
	require.True(t, (&MessageResponse{Status: StatusErrored}).IsTerminal())
	require.True(t, (&MessageResponse{Status: StatusSurrendered}).IsTerminal())
	require.False(t, (&MessageResponse{Status: StatusInProgress}).IsTerminal())
}
