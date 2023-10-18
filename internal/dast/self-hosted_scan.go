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

const ImageName = "self-hosted-dast"

func SelfHostedScan(httpClient *http.Client, nullifyHost string, input *models.ScanInput) (*models.ScanOutput, error) {
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
		Image: ImageName,
		Cmd:   []string{"/cli", string(requestBody)},
	}, nil, nil, nil, ImageName)
	if err != nil {
		logger.Error(
			"unable to create new docker container",
			logger.Err(err),
		)
		return nil, err
	}

	defer func() (*models.ScanOutput, error) {
		if err = client.ContainerRemove(ctx, containerResp.ID, types.ContainerRemoveOptions{RemoveVolumes: true, RemoveLinks: false, Force: true}); err != nil {
			logger.Error(
				"unable to remove container",
				logger.Err(err),
			)
			return nil, err
		}
		return nil, nil
	}()

	if err = client.ContainerStart(ctx, containerResp.ID, types.ContainerStartOptions{}); err != nil {
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

	return &models.ScanOutput{ScanID: "1"}, nil
}
