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

type DASTStartCloudScanInput struct {
	AppName     string            `json:"appName"`
	TargetHost  string            `json:"targetHost"`
	OpenAPISpec map[string]any    `json:"openAPISpec"`
	AuthConfig  models.AuthConfig `json:"authConfig"`

	// TODO deprecate
	Host string `json:"host"`

	models.RequestProvider
	models.RequestDashboardTarget
}

type DASTStartCloudScanOutput struct {
	ScanID string `json:"scanId"`
}

func (c *NullifyClient) DASTStartCloudScan(
	ctx context.Context,
	githubOwner string,
	input *DASTStartCloudScanInput,
) (*DASTStartCloudScanOutput, error) {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	githubID, err := GetGitHubID(ctx, githubOwner)
	if err != nil {
		return nil, err
	}
	logger.L(ctx).Debug(
		"github owner id",
		logger.String("githubOwnerId", githubID),
	)

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/dast/scans?githubOwnerId=%s", c.BaseURL, githubID),
		strings.NewReader(string(requestBody)),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, HandleError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	logger.L(ctx).Debug(
		"nullify dast start cloud scan response",
		logger.String("status", resp.Status),
		logger.String("body", string(body)),
	)

	var output DASTStartCloudScanOutput
	err = json.Unmarshal(body, &output)
	if err != nil {
		logger.L(ctx).Error(
			"error in unmarshalling response",
			logger.Err(err),
		)
		return nil, err
	}

	return &output, nil
}
