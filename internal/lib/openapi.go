package lib

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/nullify-platform/logger/pkg/logger"
	"gopkg.in/yaml.v3"
)

func CreateOpenAPIFile(filePath string) (map[string]any, error) {
	filePath = filepath.Clean(filePath)
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

	var openAPISpecAny any
	err = json.Unmarshal(fileData, &openAPISpecAny)
	if err != nil {
		err = yaml.Unmarshal(fileData, &openAPISpecAny)
		if err != nil {
			logger.Error("please provide a valid json or yaml openapi spec file")
			return nil, err
		}
	}

	openAPISpec, ok := convert(openAPISpecAny).(map[string]interface{})
	if !ok {
		logger.Error("failed to parse openapi spec")
		return nil, err
	}

	return openAPISpec, nil
}

// convert converts the map[interface{}]interface{} to map[string]interface{}.
// this is required for YAML spec files as the keys are of type interface{}
// because YAML keys can be either string or int but JSON only supports strings
func convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			switch key := k.(type) {
			case string:
				m2[key] = convert(v)
			case int:
				m2[strconv.Itoa(key)] = convert(v)
			}
		}
		return m2
	case map[string]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k] = convert(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return i
}
