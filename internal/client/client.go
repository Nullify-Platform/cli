package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nullify-platform/logger/pkg/logger"
)

type NullifyClient struct {
	Host       string
	BaseURL    string
	Token      string
	HttpClient *http.Client
}

func NewNullifyClient(nullifyHost string, token string) *NullifyClient {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &authTransport{
			nullifyHost: nullifyHost,
			token:       token,
			transport:   http.DefaultTransport,
		},
	}

	return &NullifyClient{
		Host:       nullifyHost,
		BaseURL:    "https://" + nullifyHost,
		Token:      token,
		HttpClient: httpClient,
	}
}

func (c *NullifyClient) doJSON(ctx context.Context, method, url string, input any, output any) error {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(string(requestBody)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return HandleError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	logger.L(ctx).Debug("API response", logger.String("status", resp.Status), logger.String("body", string(body)))

	if output != nil {
		return json.Unmarshal(body, output)
	}
	return nil
}

func Int(value int) *int {
	return &value
}

func String(value string) *string {
	return &value
}
