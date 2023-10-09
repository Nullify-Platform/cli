package sast

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type SASTSummaryInput struct {
	Branch   string `query:"branch"`
	Severity string `query:"severity"`

	models.RequestProvider
}

type SASTSummaryOutput struct {
	Findings []SASTFinding `json:"vulnerabilities"`
}

type SASTFinding struct {
	ULID                 string `json:"ulid"`
	Owner                string `json:"owner"`
	Repository           string `json:"repository"`
	RepositoryID         int64  `json:"repositoryId"`
	Branch               string `json:"branch"`
	UserID               int64  `json:"userId"`
	Language             string `json:"language"`
	Severity             string `json:"severity"`
	RuleID               string `json:"ruleId"`
	Entropy              string `json:"entropy"`
	FilePath             string `json:"filePath"`
	StartLine            int    `json:"startLine"`
	EndLine              int    `json:"endLine"`
	FirstCommitTimestamp string `json:"firstCommitTimestamp"`
	Timestamp            string `json:"timestamp"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
}

func GetSummary(httpClient *http.Client, nullifyHost string, input *SASTSummaryInput) (*SASTSummaryOutput, error) {
	url := fmt.Sprintf("https://%s/sast/summary?githubOwnerId=%s", nullifyHost, "123459940")

	req, err := http.NewRequest("GET", url, nil)
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

	var output SASTSummaryOutput
	err = json.Unmarshal(body, &output)
	if err != nil {
		return nil, err
	}

	return &output, nil
}
