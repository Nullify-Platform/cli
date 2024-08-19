package dast

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DASTExternalScanInput struct {
	AppName     string                 `json:"appName"`
	TargetHost  string                 `json:"targetHost"`
	OpenAPISpec map[string]interface{} `json:"openAPISpec"`
	AuthConfig  models.AuthConfig      `json:"authConfig"`
}

type DASTExternalScanOutput struct {
	Findings []models.DASTFinding `json:"findings"`
}

func RunLocalScan(
	ctx context.Context,
	nullifyClient *client.NullifyClient,
	githubOwner string,
	githubRepository string,
	input *DASTExternalScanInput,
	imageLabel string,
	forcePullImage bool,
	useHostNetwork bool,
	logLevel string,
) error {
	logger.L(ctx).Info(
		"starting local scan",
		logger.String("appName", input.AppName),
		logger.String("targetHost", input.TargetHost),
	)

	externalDASTScan, err := nullifyClient.DASTCreateExternalScan(ctx, githubOwner, &client.DASTCreateExternalScanInput{
		AppName: input.AppName,
	})
	if err != nil {
		logger.L(ctx).Error(
			"unable to create external scan",
			logger.Err(err),
		)
		return err
	}

	findings, err := runDASTInDocker(ctx, input, imageLabel, forcePullImage, useHostNetwork, logLevel)
	if err != nil {
		return err
	}

	logger.L(ctx).Info(
		"finished local scan",
		logger.Int("findingsCount", len(findings)),
	)

	err = nullifyClient.DASTUpdateExternalScan(ctx, githubOwner, githubRepository, externalDASTScan.ScanID, &client.DASTUpdateExternalScanInput{
		Progress: client.Int(100),
		Status:   client.String(client.StatusCompleted),
		Findings: findings,
	})
	if err != nil {
		logger.L(ctx).Error(
			"unable to update external scan",
			logger.Err(err),
		)
		return err
	}

	return nil
}

const maxBufferSize = 1024 * 1024

func runDASTInDocker(
	ctx context.Context,
	input *DASTExternalScanInput,
	imageLabel string,
	forcePullImage bool,
	useHostNetwork bool,
	logLevel string,
) ([]models.DASTFinding, error) {
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	dockerclient, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		logger.L(ctx).Error(
			"unable to create new docker client",
			logger.Err(err),
		)
		return nil, err
	}
	defer dockerclient.Close()

	imageRef := fmt.Sprintf("ghcr.io/nullify-platform/dast:%s", imageLabel)

	// check if image exists on local machine
	imageExists := true
	imageInspect, _, err := dockerclient.ImageInspectWithRaw(ctx, imageRef)
	if err != nil {
		imageExists = false
		logger.L(ctx).Info(
			"unable to find image on local machine",
			logger.String("imageRef", imageRef),
		)
	} else {
		logger.L(ctx).Info(
			"image found on local machine",
			logger.String("imageRef", imageRef),
			logger.String("imageID", imageInspect.ID),
		)
		logger.L(ctx).Debug(
			"image inspect",
			logger.Any("imageInspect", imageInspect),
		)
	}

	// pull image if it doesn't exist or forcePullImage is true
	if !imageExists || forcePullImage {
		err = pullImage(ctx, dockerclient, imageRef)
		if err != nil {
			return nil, err
		}
	}

	var networkMode container.NetworkMode
	if useHostNetwork {
		networkMode = "host"
	}

	containerResp, err := dockerclient.ContainerCreate(
		ctx, &container.Config{
			Image:        imageRef,
			OpenStdin:    true,
			AttachStdin:  true,
			AttachStdout: true,
			AttachStderr: true,
			Env: []string{
				fmt.Sprintf("LOG_LEVEL=%s", logLevel),
			},
		},
		&container.HostConfig{
			NetworkMode: networkMode,
		},
		nil, nil, "",
	)
	if err != nil {
		logger.L(ctx).Error(
			"unable to create new docker container",
			logger.Err(err),
		)
		return nil, err
	}

	logger.L(ctx).Debug(
		"container create response",
		logger.Any("containerResp", containerResp),
	)

	defer func() {
		err := dockerclient.ContainerRemove(ctx, containerResp.ID, container.RemoveOptions{
			Force: true,
		})
		if err != nil {
			logger.L(ctx).Error(
				"unable to remove docker container",
				logger.Err(err),
			)
		}
	}()

	err = dockerclient.ContainerStart(ctx, containerResp.ID, container.StartOptions{})
	if err != nil {
		logger.L(ctx).Error(
			"unable to start docker container",
			logger.Err(err),
		)
		return nil, err
	}

	logger.L(ctx).Debug("container started, attaching to container")

	waiter, err := dockerclient.ContainerAttach(ctx, containerResp.ID, container.AttachOptions{
		Stdin:  true,
		Stream: true,
	})
	if err != nil {
		logger.L(ctx).Error(
			"unable to attach to container",
			logger.Err(err),
		)
		return nil, err
	}

	logger.L(ctx).Debug("attached to container, writing request body to container stdin")

	_, err = waiter.Conn.Write(requestBody)
	if err != nil {
		logger.L(ctx).Error(
			"unable to write request body to container",
			logger.Err(err),
		)
		return nil, err
	}

	waiter.Close()

	logger.L(ctx).Debug("request body written to container stdin")

	containerLogs, err := dockerclient.ContainerAttach(ctx, containerResp.ID, container.AttachOptions{
		Stdout: true,
		Stderr: false,
		Stream: true,
	})
	if err != nil {
		logger.L(ctx).Error(
			"unable to create docker container logs",
			logger.Err(err),
		)
		return nil, err
	}
	defer containerLogs.Close()

	stdout, stdoutWriter := io.Pipe()
	stderr, stderrWriter := io.Pipe()

	go func() {
		defer stdoutWriter.Close()
		defer stderrWriter.Close()

		_, err := stdcopy.StdCopy(stdoutWriter, stderrWriter, containerLogs.Reader)
		if err != nil {
			logger.L(ctx).Error(
				"unable to copy container logs to stdout/stderr",
				logger.Err(err),
			)
		}
	}()

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, maxBufferSize)
	scanner.Buffer(buf, maxBufferSize)

	var lastLine string
	for scanner.Scan() {
		printDASTLocalLogLine(ctx, lastLine)
		lastLine = scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		logger.L(ctx).Error(
			"error reading output from dast local container",
			logger.Err(err),
			logger.String("lastLine", lastLine),
		)
		return nil, err
	}

	logger.L(ctx).Debug(
		"last line from dast local container",
		logger.String("lastLine", lastLine),
	)

	containerInspect, err := dockerclient.ContainerInspect(ctx, containerResp.ID)
	if err != nil {
		logger.L(ctx).Error(
			"unable to inspect container",
			logger.Err(err),
		)

		return nil, err
	}

	if containerInspect.State.ExitCode != 0 {
		printDASTLocalLogLine(ctx, lastLine)

		stderrBytes, err := io.ReadAll(stderr)
		if err != nil {
			logger.L(ctx).Error(
				"container exited with non-zero exit code",
				logger.Int("exitCode", containerInspect.State.ExitCode),
			)
		} else {
			stderrLines := strings.Split(string(stderrBytes), "\n")
			logger.L(ctx).Error(
				"container exited with non-zero exit code",
				logger.Int("exitCode", containerInspect.State.ExitCode),
				logger.Strings("stderrLines", stderrLines),
			)
		}

		return nil, fmt.Errorf("container exited with non-zero exit code")
	}

	logger.L(ctx).Debug(
		"container inspect",
		logger.Any("containerInspect", containerInspect),
	)

	// the last line before exiting is the findings
	var output DASTExternalScanOutput
	err = json.Unmarshal([]byte(lastLine), &output)
	if err != nil {
		logger.L(ctx).Error(
			"unable to unmarshal findings from dast local container",
			logger.Err(err),
		)
		return nil, err
	}

	return output.Findings, nil
}

func printDASTLocalLogLine(ctx context.Context, line string) {
	if line != "" {
		var output map[string]any
		err := json.Unmarshal([]byte(line), &output)
		if err != nil {
			fmt.Println(line)
		} else {
			logger.L(ctx).Info(
				"local scan progress",
				logger.Any("progress", output),
			)
		}
	}
}

type DockerPullOutput struct {
	Status         string                    `json:"status"`
	ID             string                    `json:"id"`
	ProgressDetail *DockerPullProgressDetail `json:"progressDetail"`
}

type DockerPullProgressDetail struct {
	Current int `json:"current"`
	Total   int `json:"total"`
}

func pullImage(ctx context.Context, dockerclient *docker.Client, imageRef string) error {
	logger.L(ctx).Info(
		"pulling image from nullify platform ghcr",
		logger.String("imageRef", imageRef),
	)

	pullOut, err := dockerclient.ImagePull(ctx, imageRef, image.PullOptions{})
	if err != nil {
		logger.L(ctx).Error(
			"unable to pull image from nullify platform ghrc",
			logger.Err(err),
		)
		return err
	}
	defer pullOut.Close()

	scanner := bufio.NewScanner(pullOut)
	buf := make([]byte, maxBufferSize)
	scanner.Buffer(buf, maxBufferSize)

	for scanner.Scan() {
		line := scanner.Text()

		var output DockerPullOutput
		err = json.Unmarshal([]byte(line), &output)
		if err != nil {
			logger.L(ctx).Error(
				"unable to unmarshal docker pull output",
				logger.Err(err),
			)
			continue
		}

		logger.L(ctx).Info(
			"docker pull progress",
			logger.Any("progress", output),
		)
	}

	if err := scanner.Err(); err != nil {
		logger.L(ctx).Error(
			"error reading output from dast local container",
			logger.Err(err),
		)
		return err
	}

	return nil
}
