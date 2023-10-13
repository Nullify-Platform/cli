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
		panic(err)
	}
	defer cli.Close()

	reader, err := cli.ImagePull(ctx, "docker.io/library/alpine", types.ImagePullOptions{})
	if err != nil {
		panic(err)
	}
	io.Copy(os.Stdout, reader)

	containerResp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "alpine",
		Cmd:   []string{"echo", "hello world"},
	}, nil, nil, nil, "")
	if err != nil {
		panic(err)
	}

	if err := cli.ContainerStart(ctx, containerResp.ID, types.ContainerStartOptions{}); err != nil {
		panic(err)
	}

	statusCh, errCh := cli.ContainerWait(ctx, containerResp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			panic(err)
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, containerResp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		panic(err)
	}

	stdcopy.StdCopy(os.Stdout, os.Stderr, out)

	// // send request with findings from dast scan
	// requestBody, err := json.Marshal(SelfHostedRequest{})
	// if err != nil {
	// 	return nil, err
	// }
	// url := fmt.Sprintf("https://%s/dast/scans", nullifyHost)

	// con := strings.NewReader(string(requestBody))
	// req, err := http.NewRequest("POST", url, con)
	// if err != nil {
	// 	return nil, err
	// }

	// req.Header.Set("Content-Type", "application/json")

	// logger.Debug(
	// 	"sending request to nullify dast",
	// 	logger.String("url", url),
	// )

	// resp, err := httpClient.Do(req)
	// if err != nil {
	// 	return nil, err
	// }
	// defer resp.Body.Close()

	// if resp.StatusCode != http.StatusOK {
	// 	return nil, client.HandleError(resp)
	// }

	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, err
	// }

	// logger.Debug(
	// 	"nullify dast response",
	// 	logger.String("status", resp.Status),
	// 	logger.String("body", string(body)),
	// )

	// var output SelfHostedOutput
	// err = json.Unmarshal(body, &output)
	// if err != nil {
	// 	return nil, err
	// }

	return nil, nil
}
