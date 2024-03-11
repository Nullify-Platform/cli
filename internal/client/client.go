package client

import (
	"net/http"
)

type NullifyClient struct {
	Host       string
	BaseURL    string
	Token      string
	HttpClient *http.Client
}

func NewNullifyClient(nullifyHost string, token string) *NullifyClient {
	httpClient := &http.Client{
		Transport: &authTransport{
			token:     token,
			transport: http.DefaultTransport,
		},
	}

	return &NullifyClient{
		Host:       nullifyHost,
		BaseURL:    "https://" + nullifyHost,
		Token:      token,
		HttpClient: httpClient,
	}
}
