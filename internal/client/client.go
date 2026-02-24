package client

import (
	"net/http"
	"time"
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

func Int(value int) *int {
	return &value
}

func String(value string) *string {
	return &value
}
