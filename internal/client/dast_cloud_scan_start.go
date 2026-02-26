package client

import (
	"context"
	"fmt"

	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DASTStartCloudScanInput struct {
	AppName     string            `json:"appName"`
	TargetHost  string            `json:"targetHost"`
	OpenAPISpec map[string]any    `json:"openAPISpec"`
	AuthConfig  models.AuthConfig `json:"authConfig"`

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
	githubID, err := GetGitHubID(ctx, githubOwner)
	if err != nil {
		return nil, err
	}
	logger.L(ctx).Debug(
		"github owner id",
		logger.String("githubOwnerId", githubID),
	)

	url := fmt.Sprintf("%s/dast/scans?githubOwnerId=%s", c.BaseURL, githubID)

	var output DASTStartCloudScanOutput
	err = c.doJSON(ctx, "POST", url, input, &output)
	if err != nil {
		return nil, err
	}

	return &output, nil
}
