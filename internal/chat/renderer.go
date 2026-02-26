package chat

import "fmt"

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiItalic = "\033[3m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// RenderToolCall renders a tool call message (dim text).
func RenderToolCall(message string) string {
	return fmt.Sprintf("%s%s[tool] %s%s", ansiDim, ansiCyan, message, ansiReset)
}

// RenderStatus renders a status message (italic text).
func RenderStatus(message string) string {
	return fmt.Sprintf("%s%s%s%s", ansiItalic, ansiYellow, message, ansiReset)
}

// RenderResponse renders a response message (normal text).
func RenderResponse(message string) string {
	return message
}

// RenderError renders an error message (red text).
func RenderError(message string) string {
	return fmt.Sprintf("%s%s%s%s", ansiBold, ansiRed, message, ansiReset)
}

// RenderMessage renders a MessageResponse based on its type.
func RenderMessage(msg MessageResponse) string {
	switch msg.MessageType {
	case MessageTypeToolCall:
		return RenderToolCall(msg.Message)
	case MessageTypeStatusMessage:
		return RenderStatus(msg.Message)
	case MessageTypeResponse:
		return RenderResponse(msg.Message)
	case MessageTypeError:
		return RenderError(msg.Message)
	default:
		return msg.Message
	}
}
