package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DASTUpdateExternalScanInput struct {
	Progress *int                 `json:"progress"`
	Status   *string              `json:"status"`
	Findings []models.DASTFinding `json:"findings"`

	*models.RequestDashboardTarget
}

func (c *NullifyClient) DASTUpdateExternalScan(
	ctx context.Context,
	githubOwner string,
	githubRepository string,
	scanID string,
	input *DASTUpdateExternalScanInput,
) error {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/dast/external/%s?githubOwner=%s", c.BaseURL, scanID, githubOwner)

	if githubRepository != "" {
		url += fmt.Sprintf("&githubRepository=%s", githubRepository)
	}

	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(requestBody)))
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

	logger.L(ctx).Debug(
		"nullify dast update external scan response",
		logger.String("status", resp.Status),
		logger.String("body", string(body)),
	)

	return nil
}
