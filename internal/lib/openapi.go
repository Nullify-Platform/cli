package lib

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/nullify-platform/logger/pkg/logger"
	"gopkg.in/yaml.v3"
)

func CreateOpenAPIFile(filePath string) (map[string]interface{}, error) {
	if strings.Contains(filePath, "/") || strings.Contains(filePath, "..") {
		return nil, errors.New("invalid file path")
	}
	data, err := os.Open(filePath)
	if err != nil {
		logger.Error(
			"failed to open open api file",
			logger.Err(err),
			logger.String("path", filePath),
		)
		return nil, err
	}
	fileData, err := io.ReadAll(data)
	if err != nil {
		logger.Error(
			"failed to read file",
			logger.Err(err),
		)
		return nil, err
	}

	var openAPISpec map[string]interface{}
	if err := json.Unmarshal(fileData, &openAPISpec); err != nil {
		if err := yaml.Unmarshal(fileData, &openAPISpec); err != nil {
			logger.Error("please provide either a json or yaml file")
			return nil, err
		}
	}
	return openAPISpec, nil
}
