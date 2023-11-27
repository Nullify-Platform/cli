package dast

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DASTLocalScanInput struct {
	AppName     string                 `json:"appName"`
	Host        string                 `json:"host"`
	TargetHost  string                 `json:"targetHost"`
	OpenAPISpec map[string]interface{} `json:"openAPISpec"`
	AuthConfig  models.AuthConfig      `json:"authConfig"`

	models.AuthSources
	models.RequestProvider
	models.RequestDashboardTarget
}

type DASTLocalScanOutput struct {
	ScanID string `json:"scanId"`
}

func DASTLocalScan(httpClient *http.Client, nullifyHost string, input *DASTLocalScanInput) error {
	logger.Info(
		"starting local scan",
		logger.String("appName", input.AppName),
		logger.String("host", input.TargetHost),
	)

	requestBody, err := json.Marshal(input)
	if err != nil {
		return err
	}

	ctx := context.Background()

	client, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logger.Error(
			"unable to create new docker client",
			logger.Err(err),
		)
		return err
	}
	defer client.Close()

	imageRef := "public.ecr.aws/nullify/dast:0.1.0"
	image, err := client.ImagePull(ctx, imageRef, types.ImagePullOptions{})
	if err != nil {
		logger.Error(
			"unable to pull image from nullify public ecr",
			logger.Err(err),
		)
		return err
	}
	defer image.Close()

	containerResp, err := client.ContainerCreate(ctx, &container.Config{
		Image: imageRef,
		Cmd:   []string{"/local", string(requestBody)},
	}, nil, nil, nil, imageRef)
	if err != nil {
		logger.Error(
			"unable to create new docker container",
			logger.Err(err),
		)
		return err
	}

	defer func() {
		if err = client.ContainerRemove(ctx, containerResp.ID, container.RemoveOptions{RemoveVolumes: true, RemoveLinks: false, Force: true}); err != nil {
			logger.Error(
				"unable to remove container",
				logger.Err(err),
			)
		}
	}()

	if err = client.ContainerStart(ctx, containerResp.ID, container.StartOptions{}); err != nil {
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

	out, err := client.ContainerLogs(ctx, containerResp.ID, container.LogsOptions{ShowStdout: true})
	if err != nil {
		logger.Error(
			"unable to create docker container logs",
			logger.Err(err),
		)
		return err
	}

	_, err = stdcopy.StdCopy(os.Stdout, os.Stderr, out)
	if err != nil {
		logger.Error(
			"unable to copy stdout from container to cli",
			logger.Err(err),
		)
		return err
	}

	return nil
}
