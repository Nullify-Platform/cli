package client

import (
	"context"
	"fmt"
	"net/url"

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
	githubID, err := GetGitHubID(ctx, githubOwner)
	if err != nil {
		return err
	}
	logger.L(ctx).Debug(
		"github owner id",
		logger.String("githubOwnerId", githubID),
	)
	reqURL := fmt.Sprintf("%s/dast/external/%s?githubOwnerId=%s", c.BaseURL, scanID, githubID)

	if githubRepository != "" {
		reqURL += fmt.Sprintf("&githubRepository=%s", url.QueryEscape(githubRepository))
	}

	return c.doJSON(ctx, "PATCH", reqURL, input, nil)
}
