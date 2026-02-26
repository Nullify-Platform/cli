package chat

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
)

// RunREPL starts an interactive chat REPL.
func RunREPL(ctx context.Context, client *Client) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sNullify Chat%s (chat ID: %s)\n", ansiBold, ansiReset, client.ChatID())
	fmt.Println("Type your message and press Enter. Press Ctrl+D to exit.")
	fmt.Println()

	// Handle Ctrl+C gracefully (cancel current request, not exit)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	for {
		fmt.Print(ansiBold + "you> " + ansiReset)

		line, err := reader.ReadString('\n')
		if err == io.EOF {
			fmt.Println("\nGoodbye!")
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		message := strings.TrimSpace(line)
		if message == "" {
			continue
		}

		if err := sendAndStream(ctx, client, message, sigCh); err != nil {
			fmt.Println(RenderError(err.Error()))
		}

		fmt.Println()
	}
}

// RunSingleShot sends a single message and streams the response.
func RunSingleShot(ctx context.Context, client *Client, message string) error {
	return sendAndStream(ctx, client, message, nil)
}

func sendAndStream(ctx context.Context, client *Client, message string, sigCh <-chan os.Signal) error {
	if err := client.Send(message); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	responses := client.ReadResponses()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sigCh:
			fmt.Println("\n(interrupted)")
			// Drain remaining responses
			for range responses {
			}
			return nil
		case resp, ok := <-responses:
			if !ok {
				return nil
			}

			rendered := RenderMessage(resp)
			if rendered != "" {
				fmt.Println(rendered)
			}

			if resp.IsTerminal() {
				return nil
			}
		}
	}
}
