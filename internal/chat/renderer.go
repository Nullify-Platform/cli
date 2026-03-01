package chat

import (
	"fmt"
	"os"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiItalic = "\033[3m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// isTTY reports whether stdout is a terminal.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ansi returns the escape code if stdout is a terminal, empty string otherwise.
func ansi(code string) string {
	if isTTY() {
		return code
	}
	return ""
}

// RenderToolCall renders a tool call message (dim text).
func RenderToolCall(message string) string {
	return fmt.Sprintf("%s%s[tool] %s%s", ansi(ansiDim), ansi(ansiCyan), message, ansi(ansiReset))
}

// RenderStatus renders a status message (italic text).
func RenderStatus(message string) string {
	return fmt.Sprintf("%s%s%s%s", ansi(ansiItalic), ansi(ansiYellow), message, ansi(ansiReset))
}

// RenderResponse renders a response message (normal text).
func RenderResponse(message string) string {
	return message
}

// RenderError renders an error message (red text).
func RenderError(message string) string {
	return fmt.Sprintf("%s%s%s%s", ansi(ansiBold), ansi(ansiRed), message, ansi(ansiReset))
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
