package dast

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type SelfHostedInput struct {
	AppName     string                 `json:"appName"`
	Host        string                 `json:"host"`
	TargetHost  string                 `json:"targetHost"`
	OpenAPISpec map[string]interface{} `json:"openAPISpec"`
	AuthConfig  StartScanAuthConfig    `json:"authConfig"`

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
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	client, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		logger.Error(
			"unable to create new docker client",
			logger.Err(err),
		)
		return nil, err
	}
	defer client.Close()

	// reader, err := client.ImagePull(ctx, "docker.io/library/alpine", types.ImagePullOptions{})
	// if err != nil {
	// 	logger.Error(
	// 		"unable to pull image from docker public registry",
	// 		logger.Err(err),
	// 	)
	// 	return nil, err
	// }
	// io.Copy(os.Stdout, reader)

	containerResp, err := client.ContainerCreate(ctx, &container.Config{
		Image: "self-hosted-dast",
		Cmd:   []string{"/cli", string(requestBody)},
	}, nil, nil, nil, "self-hosted-dast-1")
	if err != nil {
		logger.Error(
			"unable to create new docker container",
			logger.Err(err),
		)
		return nil, err
	}

	if err := client.ContainerStart(ctx, containerResp.ID, types.ContainerStartOptions{}); err != nil {
		logger.Error(
			"unable to start docker container",
			logger.Err(err),
		)
		return nil, err
	}

	statusCh, errCh := client.ContainerWait(ctx, containerResp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			logger.Error(
				"unable to create new docker clientent",
				logger.Err(err),
			)
			return nil, err
		}
	case <-statusCh:
	}

	out, err := client.ContainerLogs(ctx, containerResp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		logger.Error(
			"unable to create docker container logs",
			logger.Err(err),
		)
		return nil, err
	}

	stdcopy.StdCopy(os.Stdout, os.Stderr, out)

	return &SelfHostedOutput{ScanID: "1"}, nil
}
