package client

import (
	"context"
	"fmt"
	"time"

	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DASTCreateExternalScanInput struct {
	AppName string `json:"appName"`

	Progress  *int       `json:"progress"`
	Status    *string    `json:"status"`
	StartTime *time.Time `json:"startTime"`
	EndTime   *time.Time `json:"endTime"`

	models.RequestProvider
	models.RequestDashboardTarget
}

type DASTCreateExternalScanOutput struct {
	ScanID string `json:"scanId"`
}

func (c *NullifyClient) DASTCreateExternalScan(
	ctx context.Context,
	githubOwner string,
	input *DASTCreateExternalScanInput,
) (*DASTCreateExternalScanOutput, error) {
	logger.L(ctx).Info(
		"creating external scan",
		logger.String("appName", input.AppName),
		logger.String("baseURL", c.BaseURL),
	)

	githubID, err := GetGitHubID(ctx, githubOwner)
	if err != nil {
		return nil, err
	}
	logger.L(ctx).Debug(
		"github owner id",
		logger.String("githubOwnerId", githubID),
	)

	url := fmt.Sprintf("%s/dast/external?githubOwnerId=%s", c.BaseURL, githubID)

	var output DASTCreateExternalScanOutput
	err = c.doJSON(ctx, "POST", url, input, &output)
	if err != nil {
		return nil, err
	}

	return &output, nil
}
