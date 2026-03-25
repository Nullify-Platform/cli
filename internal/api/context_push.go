package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// ContextCredentialsRequest is the request body for POST /admin/context/credentials.
type ContextCredentialsRequest struct {
	ContextType string `json:"contextType"`
	Repository  string `json:"repository"`
	Branch      string `json:"branch,omitempty"`
	Environment string `json:"environment,omitempty"`
	Name        string `json:"name"`
	PRNumber    int    `json:"prNumber,omitempty"`
	FromPR      int    `json:"fromPR,omitempty"`
	CommitSHA   string `json:"commitSha,omitempty"`
}

// ContextCredentialsResponse is the response from POST /admin/context/credentials.
type ContextCredentialsResponse struct {
	Credentials struct {
		AccessKeyID     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
		SessionToken    string `json:"sessionToken"`
		Expiration      string `json:"expiration"`
	} `json:"credentials"`
	Bucket    string `json:"bucket"`
	KeyPrefix string `json:"keyPrefix"`
	KMSKeyARN string `json:"kmsKeyArn,omitempty"`
	Region    string `json:"region"`
}

// PostContextCredentials requests scoped STS credentials for uploading context data.
func (c *Client) PostContextCredentials(ctx context.Context, req ContextCredentialsRequest) (*ContextCredentialsResponse, error) {
	path := "/admin/context/credentials"

	query := url.Values{}
	for k, v := range c.DefaultParams {
		query.Set(k, v)
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	respBody, err := c.do(ctx, "POST", c.BaseURL+path+"?"+query.Encode(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	var resp ContextCredentialsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &resp, nil
}
