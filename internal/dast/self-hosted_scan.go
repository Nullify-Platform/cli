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

type SelfHostedScanInput struct {
	AppName     string                 `json:"appName"`
	Host        string                 `json:"host"`
	TargetHost  string                 `json:"targetHost"`
	OpenAPISpec map[string]interface{} `json:"openAPISpec"`
	AuthConfig  models.AuthConfig      `json:"authConfig"`

	models.AuthSources
	models.RequestProvider
	models.RequestDashboardTarget
}

type SelfHostedScanOutput struct {
	ScanID string `json:"scanId"`
}

const ImageName = "self-hosted-dast"

func SelfHostedScan(httpClient *http.Client, nullifyHost string, input *SelfHostedScanInput) error {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return err
	}

	ctx := context.Background()

	client, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		logger.Error(
			"unable to create new docker client",
			logger.Err(err),
		)
		return err
	}
	defer client.Close()

	// TODO add image to public repository
	// reader, err := client.ImagePull(ctx, "docker.io/library/alpine", types.ImagePullOptions{})
	// if err != nil {
	// 	logger.Error(
	// 		"unable to pull image from docker public registry",
	// 		logger.Err(err),
	// 	)
	// 	return err
	// }
	// io.Copy(os.Stdout, reader)

	containerResp, err := client.ContainerCreate(ctx, &container.Config{
		Image: ImageName,
		Cmd:   []string{"/cli", string(requestBody)},
	}, nil, nil, nil, ImageName)
	if err != nil {
		logger.Error(
			"unable to create new docker container",
			logger.Err(err),
		)
		return err
	}

	defer func() error {
		if err = client.ContainerRemove(ctx, containerResp.ID, types.ContainerRemoveOptions{RemoveVolumes: true, RemoveLinks: false, Force: true}); err != nil {
			logger.Error(
				"unable to remove container",
				logger.Err(err),
			)
			return err
		}
		return nil
	}()

	if err = client.ContainerStart(ctx, containerResp.ID, types.ContainerStartOptions{}); err != nil {
		logger.Error(
			"unable to start docker container",
			logger.Err(err),
		)
		return err
	}

	statusCh, errCh := client.ContainerWait(ctx, containerResp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			logger.Error(
				"error while waiting for container to finish scan",
				logger.Err(err),
			)
			return err
		}
	case <-statusCh:
	}

	out, err := client.ContainerLogs(ctx, containerResp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		logger.Error(
			"unable to create docker container logs",
			logger.Err(err),
		)
		return err
	}

	stdcopy.StdCopy(os.Stdout, os.Stderr, out)

	return nil
}
