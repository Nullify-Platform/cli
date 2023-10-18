package models

type ScanInput struct {
	AppName     string                 `json:"appName"`
	Host        string                 `json:"host"`
	TargetHost  string                 `json:"targetHost"`
	OpenAPISpec map[string]interface{} `json:"openAPISpec"`
	AuthConfig  ScanAuthConfig         `json:"authConfig"`

	RequestProvider
	RequestDashboardTarget
}

type ScanAuthConfig struct {
	Headers map[string]string `json:"headers"`
}

type ScanOutput struct {
	ScanID string `json:"scanId"`
}
