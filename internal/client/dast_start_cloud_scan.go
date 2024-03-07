package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DASTStartCloudScanInput struct {
	AppName    string            `json:"appName"`
	TargetHost string            `json:"targetHost"`
	Spec       string            `json:"spec"`
	AuthConfig models.AuthConfig `json:"authConfig"`

	// TODO deprecate
	Host string `json:"host"`

	models.RequestProvider
	models.RequestDashboardTarget
}

type StartCloudScanOutput struct {
	ScanID string `json:"scanId"`
}

func (c *NullifyClient) DASTStartCloudScan(input *DASTStartCloudScanInput) (*StartCloudScanOutput, error) {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/dast/scans", c.baseURL),
		strings.NewReader(string(requestBody)),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
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

	logger.Debug(
		"nullify dast response",
		logger.String("status", resp.Status),
		logger.String("body", string(body)),
	)

	var output StartCloudScanOutput
	err = json.Unmarshal(body, &output)
	if err != nil {
		logger.Error(
			"error in unmarshalling response",
			logger.Err(err),
		)
		return nil, err
	}

	return &output, nil
}
