package dast

import (
	"context"
	"io"
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
	ctx := context.Background()

	cli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		logger.Error(
			"unable to create new docker client",
			logger.Err(err),
		)
		return nil, err
	}
	defer cli.Close()

	reader, err := cli.ImagePull(ctx, "docker.io/library/alpine", types.ImagePullOptions{})
	if err != nil {
		logger.Error(
			"unable to pull image from docker public registry",
			logger.Err(err),
		)
		return nil, err
	}
	io.Copy(os.Stdout, reader)

	containerResp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "alpine",
		Cmd:   []string{"echo", "hello world"},
	}, nil, nil, nil, "")
	if err != nil {
		logger.Error(
			"unable to create new docker container",
			logger.Err(err),
		)
		return nil, err
	}

	if err := cli.ContainerStart(ctx, containerResp.ID, types.ContainerStartOptions{}); err != nil {
		logger.Error(
			"unable to start docker container",
			logger.Err(err),
		)
		return nil, err
	}

	statusCh, errCh := cli.ContainerWait(ctx, containerResp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			logger.Error(
				"unable to create new docker client",
				logger.Err(err),
			)
			return nil, err
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, containerResp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		logger.Error(
			"unable to create docker container logs",
			logger.Err(err),
		)
		return nil, err
	}

	stdcopy.StdCopy(os.Stdout, os.Stderr, out)

	return nil, nil
}
