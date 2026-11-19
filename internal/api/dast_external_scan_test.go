package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/api/models"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Body   string
}

func externalScanServer(t *testing.T, response string) (*Client, *[]recordedRequest) {
	t.Helper()
	var requests []recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		requests = append(requests, recordedRequest{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Body: string(body)})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)

	c := NewClient("acme.nullify.ai", "test-token", map[string]string{"githubOwnerId": "42"})
	c.HTTPClient = &http.Client{Transport: deliverTo(server)}
	return c, &requests
}

func TestCreateExternalPentestScan(t *testing.T) {
	c, requests := externalScanServer(t, `{"scanId":"scan-1"}`)
	status := models.ModelsScanStatusInProgress
	start := time.Date(2026, 11, 19, 1, 2, 3, 0, time.UTC)

	out, err := c.CreateExternalPentestScan(context.Background(), CreateExternalPentestScanInput{
		AppID:     "app-1",
		Status:    &status,
		StartTime: &start,
	})

	require.NoError(t, err)
	require.Equal(t, "scan-1", out.ScanID)
	require.Equal(t, []recordedRequest{{
		Method: "POST",
		Path:   "/dast/pentest/scans/external",
		Query:  "githubOwnerId=42",
		Body:   `{"appId":"app-1","status":"in progress","startTime":"2026-11-19T01:02:03Z"}`,
	}}, *requests)
}

func TestUpdateExternalPentestScanSendsNullFindings(t *testing.T) {
	c, requests := externalScanServer(t, `{"scan":{"id":"scan/1","status":"failed"}}`)
	status := models.ModelsScanStatusFailed

	out, err := c.UpdateExternalPentestScan(context.Background(), UpdateExternalPentestScanInput{
		ScanID:       "scan/1",
		Status:       &status,
		RequestScope: models.RequestScope{GithubOwnerID: 7},
	})

	require.NoError(t, err)
	require.Equal(t, models.ModelsScanStatusFailed, out.Scan.Status)
	require.Equal(t, []recordedRequest{{
		Method: "PATCH",
		Path:   "/dast/pentest/scans/external/scan%2F1",
		Query:  "githubOwnerId=7",
		Body:   `{"status":"failed","findings":null}`,
	}}, *requests)
}

func TestUpdateExternalPentestScanRequiresAScanID(t *testing.T) {
	c, requests := externalScanServer(t, `{}`)

	_, err := c.UpdateExternalPentestScan(context.Background(), UpdateExternalPentestScanInput{})

	require.ErrorContains(t, err, "scan id is required")
	require.Empty(t, *requests)
}

// TestExternalPentestFindingMatchesTheSpec checks the upload against the
// pentest finding schema in the vendored spec. The API refuses a field it
// does not know and requires every required field, so a key that drifts
// either way fails the upload after the scan has run.
func TestExternalPentestFindingMatchesTheSpec(t *testing.T) {
	schemas := loadSpecSchemas(t)
	finding := ExternalPentestFinding{
		ScanInfo: models.ModelsPentestFindingScanInfo{ScanType: models.ModelsPentestFindingScanTypeApi},
		Source:   models.ModelsPentestFindingSourceZap,
		API: &ExternalPentestFindingAPI{
			Severity:        models.ModelsSeverityHigh,
			QueryParameters: map[string]string{"q": "x"},
			RequestHeader:   map[string]string{},
			ResponseHeader:  map[string]string{},
		},
		PriorityLabel: models.ModelsPriorityLabelUnknown,
	}
	data, err := json.Marshal(finding)
	require.NoError(t, err)
	var value map[string]any
	require.NoError(t, json.Unmarshal(data, &value))

	checkAgainstSchema(t, schemas, "ModelsPentestFinding", value, "finding")
}

func loadSpecSchemas(t *testing.T) map[string]map[string]any {
	t.Helper()
	data, err := os.ReadFile(specFile)
	require.NoError(t, err)
	var spec struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	require.NoError(t, yaml.Unmarshal(data, &spec))
	require.NotEmpty(t, spec.Components.Schemas)
	return spec.Components.Schemas
}

func checkAgainstSchema(t *testing.T, schemas map[string]map[string]any, name string, value any, at string) {
	t.Helper()
	schema, ok := schemas[name]
	require.True(t, ok, "the spec has no schema %s", name)

	if enum, ok := schema["enum"].([]any); ok {
		require.Contains(t, enum, value, "%s: not a value of %s", at, name)
		return
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return
	}
	object, ok := value.(map[string]any)
	require.True(t, ok, "%s: want an object for %s", at, name)

	for key, v := range object {
		property, ok := properties[key].(map[string]any)
		require.True(t, ok, "%s.%s: %s has no such field, so the API refuses it", at, key, name)
		if ref, ok := property["$ref"].(string); ok {
			checkAgainstSchema(t, schemas, strings.TrimPrefix(ref, "#/components/schemas/"), v, at+"."+key)
		}
	}
	required, _ := schema["required"].([]any)
	for _, key := range required {
		require.Contains(t, object, key, "%s: %s requires %s", at, name, key)
	}
}
