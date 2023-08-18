package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type errorBody struct {
	Error string `json:"error"`
}

func HandleError(resp *http.Response) error {
	if resp.Header.Get("Content-Type") != "application/json" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf(
				"unexpected content-type %d",
				resp.StatusCode,
			)
		}

		return fmt.Errorf(
			"unexpected status code %d: %s",
			resp.StatusCode,
			string(body),
		)
	}

	body := errorBody{}
	err := json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return err
	}

	return fmt.Errorf(
		"unexpected status code %d: %s",
		resp.StatusCode,
		body.Error,
	)
}
