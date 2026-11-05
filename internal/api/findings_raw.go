package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/nullify-platform/cli/internal/api/models"
)

// CreateAdminFindingsRaw sends POST /admin/findings like CreateAdminFindings, and
// returns the response body as the server sent it. A finding then keeps the fields
// that the generated models do not have, and a changed field type cannot fail a list.
func (c *Client) CreateAdminFindingsRaw(ctx context.Context, q models.ModelsUnifiedFindingsQuery) ([]byte, error) {
	body, err := json.Marshal(struct {
		Query models.ModelsUnifiedFindingsQuery `json:"query"`
	}{Query: q})
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}

	return c.do(ctx, "POST", c.defaultParamsURL("/admin/findings"), bytes.NewReader(body))
}

// GetRaw sends a GET and returns the response body as the server sent it.
func (c *Client) GetRaw(ctx context.Context, path string) ([]byte, error) {
	return c.do(ctx, "GET", c.defaultParamsURL(path), nil)
}

func (c *Client) defaultParamsURL(path string) string {
	query := url.Values{}
	for k, v := range c.DefaultParams {
		query.Set(k, v)
	}

	if len(query) == 0 {
		return c.BaseURL + path
	}
	return c.BaseURL + path + "?" + query.Encode()
}
