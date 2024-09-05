package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	logger.L(ctx).Info(
		"creating external scan",
		logger.String("appName", input.AppName),
		logger.String("baseURL", c.BaseURL),
	)

	githubID, err := GetGitHubIDFromString(ctx, githubOwner)
	if err != nil {
		return nil, err
	}
	logger.L(ctx).Debug(
		"github owner id",
		logger.String("githubOwnerId", githubID),
	)

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/dast/external?githubOwnerId=%s", c.BaseURL, githubID),
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
		"nullify dast create external scan response",
		logger.String("status", resp.Status),
		logger.String("body", string(body)),
	)

	var output DASTCreateExternalScanOutput
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
