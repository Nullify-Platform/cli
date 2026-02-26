package chat

// Status constants matching the-holonet protocol.
const (
	StatusInProgress = "In Progress"
	StatusFinished   = "Finished"
	StatusErrored    = "Errored"
	StatusSurrendered = "Surrendered"
)

// MessageType constants matching the-holonet protocol.
const (
	MessageTypeToolCall      = "toolCall"
	MessageTypeStatusMessage = "statusMessage"
	MessageTypeResponse      = "response"
	MessageTypeError         = "error"
)

// Payload is the message sent to the Nullify chat WebSocket.
type Payload struct {
	OwnerProvider     map[string]string `json:"ownerProvider"`
	ChatID            string            `json:"chatID"`
	Message           string            `json:"message"`
	ExtraSystemPrompt string            `json:"extraSystemPrompt"`
}

// MessageResponse is a message received from the Nullify chat WebSocket.
type MessageResponse struct {
	Status      string `json:"status"`
	MessageType string `json:"messageType"`
	Message     string `json:"message"`
}

// IsTerminal returns true if this response indicates the conversation turn is complete.
func (m *MessageResponse) IsTerminal() bool {
	return m.Status == StatusFinished || m.Status == StatusErrored || m.Status == StatusSurrendered
}
