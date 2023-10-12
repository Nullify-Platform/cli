package dast

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type SelfHostedInput struct {
	AppName     string                 `json:"appName"`
	Host        string                 `json:"host"`
	OpenAPISpec map[string]interface{} `json:"openAPISpec"`
	AuthConfig  StartScanAuthConfig    `json:"authConfig"`
	Image       string                 `json:"image"`

	models.RequestProvider
	models.RequestDashboardTarget
}

type SelfHostedRequest struct {
	AppName  string               `json:"appName"`
	Findings []models.DASTFinding `json:"findings"`

	models.RequestProvider
	models.RequestDashboardTarget
}

type SelfHostedConfig struct {
	Headers map[string]string `json:"headers"`
}

type SelfHostedOutput struct {
	ScanID string `json:"scanId"`
}

func SelfHostedScan(httpClient *http.Client, nullifyHost string, input *SelfHostedInput) (*SelfHostedOutput, error) {
	cmd := exec.Command("docker", "run", input.Image)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		return nil, err
	}

	err = cmd.Wait()
	if err != nil {
		return nil, err
	}

	// send request with findings from dast scan
	requestBody, err := json.Marshal(SelfHostedRequest{})
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

	var output SelfHostedOutput
	err = json.Unmarshal(body, &output)
	if err != nil {
		return nil, err
	}

	return &output, nil
}
