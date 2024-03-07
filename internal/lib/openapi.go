package lib

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/nullify-platform/logger/pkg/logger"
	"gopkg.in/yaml.v3"
)

func CreateOpenAPIFile(filePath string) (string, error) {
	filePath = filepath.Clean(filePath)
	data, err := os.Open(filePath)
	if err != nil {
		logger.Error(
			"failed to open open api file",
			logger.Err(err),
			logger.String("path", filePath),
		)
		return "", err
	}

	fileData, err := io.ReadAll(data)
	if err != nil {
		logger.Error(
			"failed to read file",
			logger.Err(err),
		)
		return "", err
	}

	var openAPISpec map[string]interface{}
	if err := json.Unmarshal(fileData, &openAPISpec); err != nil {
		if err := yaml.Unmarshal(fileData, &openAPISpec); err != nil {
			logger.Error("please provide a valid json or yaml openapi spec file")
			return "", err
		}
	}

	return string(fileData), nil
}
