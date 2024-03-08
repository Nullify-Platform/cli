package client

import (
	"net/http"
)

type NullifyClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewNullifyClient(nullifyHost string, token string) *NullifyClient {
	httpClient := &http.Client{
		Transport: &authTransport{
			token:     token,
			transport: http.DefaultTransport,
		},
	}

	return &NullifyClient{
		baseURL:    "https://" + nullifyHost,
		httpClient: httpClient,
	}
}
