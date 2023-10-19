package dast

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type StartScanInput struct {
	AppName     string                 `json:"appName"`
	Host        string                 `json:"host"`
	OpenAPISpec map[string]interface{} `json:"openAPISpec"`
	AuthConfig  models.AuthConfig      `json:"authConfig"`

	models.RequestProvider
	models.RequestDashboardTarget
}

type StartScanOutput struct {
	ScanID string `json:"scanId"`
}

func StartScan(httpClient *http.Client, nullifyHost string, input *StartScanInput) (*StartScanOutput, error) {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s/dast/scans", nullifyHost)

	con := strings.NewReader(string(requestBody))
	req, err := http.NewRequest("POST", url, con)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	logger.Debug(
		"sending request to nullify dast",
		logger.String("url", url),
	)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, client.HandleError(resp)
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

	var output StartScanOutput
	err = json.Unmarshal(body, &output)
	if err != nil {
		return nil, err
	}

	return &output, nil
}
