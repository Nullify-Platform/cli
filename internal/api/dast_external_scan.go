package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/nullify-platform/cli/internal/api/models"
)

// The external scan routes record a pentest that ran outside Nullify, such
// as a local scan. The API serves them but leaves them out of the published
// spec, so the generated client has no methods for them.
const (
	externalScanCreatePath = "/dast/pentest/scans/external"
	externalScanUpdatePath = "/dast/pentest/scans/external/"
)

// CreateExternalPentestScanInput is the body of POST
// /dast/pentest/scans/external. The application must exist in Nullify.
type CreateExternalPentestScanInput struct {
	AppID     string                   `json:"appId"`
	Progress  *int                     `json:"progress,omitempty"`
	Status    *models.ModelsScanStatus `json:"status,omitempty"`
	StartTime *time.Time               `json:"startTime,omitempty"`

	models.RequestScope `json:"-"`
}

// CreateExternalPentestScanOutput is the response of POST
// /dast/pentest/scans/external.
type CreateExternalPentestScanOutput struct {
	ScanID string `json:"scanId"`
}

// UpdateExternalPentestScanInput is the body of PATCH
// /dast/pentest/scans/external/{scanId}. Findings are allowed only with
// status completed and progress 100. A nil Findings is sent as null, which
// the API requires to be present.
type UpdateExternalPentestScanInput struct {
	ScanID   string                   `json:"-"`
	Progress *int                     `json:"progress,omitempty"`
	Status   *models.ModelsScanStatus `json:"status,omitempty"`
	Findings []ExternalPentestFinding `json:"findings"`

	models.RequestScope `json:"-"`
}

// UpdateExternalPentestScanOutput is the response of PATCH
// /dast/pentest/scans/external/{scanId}.
type UpdateExternalPentestScanOutput struct {
	Scan models.ModelsPentestScan `json:"scan"`
}

// ExternalPentestFinding is a finding as the external scan update accepts
// it. It is the API's pentest finding with only the fields an external
// scanner sets. The API refuses unknown fields and requires every field
// here, so none of them is omitted when empty. The API derives the id and
// fills in the scan, application and target.
type ExternalPentestFinding struct {
	ID                string                              `json:"id"`
	ScanInfo          models.ModelsPentestFindingScanInfo `json:"scanInfo"`
	Title             string                              `json:"title"`
	Summary           string                              `json:"summary"`
	CWE               int                                 `json:"cwe"`
	Source            models.ModelsPentestFindingSource   `json:"source"`
	Endpoint          models.ModelsPentestFindingEndpoint `json:"endpoint"`
	API               *ExternalPentestFindingAPI          `json:"api"`
	Host              string                              `json:"host"`
	IsLatest          bool                                `json:"isLatest"`
	IsFixed           bool                                `json:"isFixed"`
	IsAllowlisted     bool                                `json:"isAllowlisted"`
	IsArchived        bool                                `json:"isArchived"`
	IsFalsePositive   bool                                `json:"isFalsePositive"`
	AllowlistedReason string                              `json:"allowlistedReason"`
	CreatedAt         time.Time                           `json:"createdAt"`
	UpdatedAt         time.Time                           `json:"updatedAt"`
	IsAutoFixable     bool                                `json:"isAutoFixable"`
	PriorityLabel     models.ModelsPriorityLabel          `json:"priorityLabel"`
	PriorityScore     int                                 `json:"priorityScore"`
}

// ExternalPentestFindingAPI is the request and response evidence of an API
// finding. The generated model cannot carry the header and query maps, so
// this type declares them.
type ExternalPentestFindingAPI struct {
	Severity                 models.ModelsSeverity `json:"severity"`
	Solution                 string                `json:"solution"`
	ErrorDescription         string                `json:"errorDescription"`
	ErrorType                string                `json:"errorType"`
	HTTPVersion              string                `json:"httpVersion"`
	Method                   string                `json:"method"`
	Path                     string                `json:"path"`
	PreviousResponse         string                `json:"previousResponse"`
	QueryParameters          map[string]string     `json:"queryParameters"`
	RequestBody              string                `json:"requestBody"`
	RequestHeader            map[string]string     `json:"requestHeader"`
	ResponseBody             string                `json:"responseBody"`
	ResponseHeader           map[string]string     `json:"responseHeader"`
	URI                      string                `json:"uri"`
	VulnerableParameterName  string                `json:"vulnerableParameterName"`
	VulnerableParameterValue string                `json:"vulnerableParameterValue"`
}

// CreateExternalPentestScan sends POST /dast/pentest/scans/external and
// returns the id of the new scan. The caller that creates the scan is the
// only one, apart from Nullify staff, that can update it.
func (c *Client) CreateExternalPentestScan(ctx context.Context, in CreateExternalPentestScanInput) (*CreateExternalPentestScanOutput, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}

	resp, err := c.do(ctx, "POST", c.scopedURL(externalScanCreatePath, in.RequestScope), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var out CreateExternalPentestScanOutput
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// UpdateExternalPentestScan sends PATCH /dast/pentest/scans/external/{scanId}
// and returns the scan as stored.
func (c *Client) UpdateExternalPentestScan(ctx context.Context, in UpdateExternalPentestScanInput) (*UpdateExternalPentestScanOutput, error) {
	if in.ScanID == "" {
		return nil, fmt.Errorf("update external pentest scan: scan id is required")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}

	path := externalScanUpdatePath + url.PathEscape(in.ScanID)
	resp, err := c.do(ctx, "PATCH", c.scopedURL(path, in.RequestScope), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var out UpdateExternalPentestScanOutput
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// scopedURL is path on the API with the client's default parameters and the
// request scope as its query.
func (c *Client) scopedURL(path string, scope models.RequestScope) string {
	query := url.Values{}
	for k, v := range c.DefaultParams {
		query.Set(k, v)
	}
	scope.AddTo(query)

	if len(query) == 0 {
		return c.BaseURL + path
	}
	return c.BaseURL + path + "?" + query.Encode()
}
