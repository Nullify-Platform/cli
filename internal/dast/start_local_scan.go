package dast

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DASTExternalScanInput struct {
	AppName      string            `json:"appName"`
	Host         string            `json:"host"`
	TargetHost   string            `json:"targetHost"`
	Version      string            `json:"version"`
	OpenAPISpec  map[string]any    `json:"openAPISpec"`
	AuthConfig   models.AuthConfig `json:"authConfig"`
	NullifyToken string            `json:"nullifyToken"`

	models.RequestProvider
	models.RequestDashboardTarget
}

type DASTExternalScanOutput struct {
	Findings []models.DASTFinding `json:"findings"`
}

func StartExternalScan(
	ctx context.Context,
	nullifyClient *client.NullifyClient,
	githubOwner string,
	input *DASTExternalScanInput,
	forcePullImage bool,
	logLevel string,
) error {
	logger.Info(
		"starting local scan",
		logger.String("appName", input.AppName),
		logger.String("host", input.TargetHost),
	)

	externalDASTScan, err := nullifyClient.DASTCreateExternalScan(githubOwner, &client.DASTCreateExternalScanInput{
		AppName: input.AppName,
	})
	if err != nil {
		logger.Error(
			"unable to create external scan",
			logger.Err(err),
		)
		return err
	}

	findings, err := runDASTInDocker(ctx, input, forcePullImage, logLevel)
	if err != nil {
		return err
	}

	logger.Info(
		"finished local scan",
		logger.Int("findingsCount", len(findings)),
	)

	err = nullifyClient.DASTUpdateExternalScan(githubOwner, externalDASTScan.ScanID, &client.DASTUpdateExternalScanInput{
		Findings: findings,
	})
	if err != nil {
		logger.Error(
			"unable to update external scan",
			logger.Err(err),
		)
		return err
	}

	return nil
}

const initialBufferSize = 64 * 1024
const maxBufferSize = 1024 * 1024

func runDASTInDocker(
	ctx context.Context,
	input *DASTExternalScanInput,
	forcePullImage bool,
	logLevel string,
) ([]models.DASTFinding, error) {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	dockerclient, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		logger.Error(
			"unable to create new docker client",
			logger.Err(err),
		)
		return nil, err
	}
	defer dockerclient.Close()

	imageRef := fmt.Sprintf("ghcr.io/nullify-platform/dast-local:%s", input.Version)

	// check if image exists on local machine
	imageExists := true
	_, _, err = dockerclient.ImageInspectWithRaw(ctx, imageRef)
	if err != nil {
		imageExists = false
		logger.Info(
			"unable to find image on local machine, pulling from nullify platform ghcr",
			logger.String("imageRef", imageRef),
		)
	}

	// pull image if it doesn't exist or forcePullImage is true
	if !imageExists || forcePullImage {
		pullOut, err := dockerclient.ImagePull(ctx, imageRef, types.ImagePullOptions{})
		if err != nil {
			logger.Error(
				"unable to pull image from nullify platform ghrc",
				logger.Err(err),
			)
			return nil, err
		}
		defer pullOut.Close()

		_, err = io.Copy(os.Stdout, pullOut)
		if err != nil {
			logger.Error(
				"unable to copy image pull output to stdout",
				logger.Err(err),
			)
			return nil, err
		}
	}

	containerResp, err := dockerclient.ContainerCreate(
		ctx, &container.Config{
			Image:        imageRef,
			Tty:          true,
			OpenStdin:    true,
			AttachStdin:  true,
			AttachStdout: true,
			AttachStderr: true,
			Env: []string{
				fmt.Sprintf("LOG_LEVEL=%s", logLevel),
			},
		},
		&container.HostConfig{
			AutoRemove:  true,
			NetworkMode: "host",
		},
		nil, nil, "",
	)
	if err != nil {
		logger.Error(
			"unable to create new docker container",
			logger.Err(err),
		)
		return nil, err
	}

	err = dockerclient.ContainerStart(ctx, containerResp.ID, container.StartOptions{})
	if err != nil {
		logger.Error(
			"unable to start docker container",
			logger.Err(err),
		)
		return nil, err
	}

	hijackedResponse, err := dockerclient.ContainerAttach(ctx, containerResp.ID, container.AttachOptions{
		Stderr: true,
		Stdout: true,
		Stdin:  true,
		Stream: true,
	})
	if err != nil {
		logger.Error(
			"unable to attach to container",
			logger.Err(err),
		)
		return nil, err
	}

	_, err = hijackedResponse.Conn.Write(append(requestBody, '\n'))
	if err != nil {
		logger.Error(
			"unable to write request body to container",
			logger.Err(err),
		)
		return nil, err
	}

	err = hijackedResponse.Conn.Close()
	if err != nil {
		logger.Error(
			"unable to close connection to container",
			logger.Err(err),
		)
		return nil, err
	}

	logsOut, err := dockerclient.ContainerLogs(ctx, containerResp.ID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		logger.Error(
			"unable to create docker container logs",
			logger.Err(err),
		)
		return nil, err
	}

	defer logsOut.Close()

	var lastLine string

	scanner := bufio.NewScanner(logsOut)
	buf := make([]byte, 0, initialBufferSize)
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		if lastLine != "" {
			var output map[string]any
			err = json.Unmarshal([]byte(lastLine), &output)
			if err != nil {
				fmt.Println(lastLine)
			} else {
				logger.Info(
					"local scan progress",
					logger.Any("progress", output),
				)
			}
		}

		lastLine = scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		logger.Error(
			"error reading output from dast local container",
			logger.Err(err),
		)
		return nil, err
	}

	// the last line before exiting is the findings
	var output DASTExternalScanOutput
	err = json.Unmarshal([]byte(lastLine), &output)
	if err != nil {
		logger.Error(
			"unable to unmarshal findings from dast local container",
			logger.Err(err),
		)
		return nil, err
	}

	return output.Findings, nil
}
