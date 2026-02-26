package models

// AuthConfig represents the authentication configuration for Nullify DAST
type AuthConfig struct {
	// Single user authentication fields
	Method          string                 `json:"method,omitempty"`
	Username        string                 `json:"username,omitempty"`
	UserDescription string                 `json:"userDescription,omitempty"`
	Headers         map[string]string      `json:"headers,omitempty"`
	Password        string                 `json:"password,omitempty"`
	Token           string                 `json:"token,omitempty"`
	ClientID        string                 `json:"clientId,omitempty"`
	ClientSecret    string                 `json:"clientSecret,omitempty"`
	TokenURL        string                 `json:"tokenUrl,omitempty"`
	Scope           string                 `json:"scope,omitempty"`
	LoginURL        string                 `json:"loginUrl,omitempty"`
	LoginBody       interface{}            `json:"loginBody,omitempty"`
	LoginSelector   string                 `json:"loginSelector,omitempty"`
	CustomHeaders   map[string]string      `json:"customHeaders,omitempty"`
	CustomParams    map[string]interface{} `json:"customParams,omitempty"`

	// Multi-user authentication fields
	AuthorizationModel bool       `json:"authorizationModel,omitempty"`
	Users              []UserAuth `json:"users,omitempty"`
}

type UserAuth struct {
	RoleName        string              `json:"roleName"`
	RoleDescription string              `json:"roleDescription,omitempty"`
	UserDescription string              `json:"userDescription,omitempty"`
	AuthConfig      MultiUserAuthConfig `json:"authConfig"`
}

type MultiUserAuthConfig struct {
	Method        string                 `json:"method,omitempty"`
	Username      string                 `json:"username,omitempty"`
	Password      string                 `json:"password,omitempty"`
	Token         string                 `json:"token,omitempty"`
	ClientID      string                 `json:"clientId,omitempty"`
	ClientSecret  string                 `json:"clientSecret,omitempty"`
	TokenURL      string                 `json:"tokenUrl,omitempty"`
	Scope         string                 `json:"scope,omitempty"`
	LoginURL      string                 `json:"loginUrl,omitempty"`
	LoginBody     interface{}            `json:"loginBody,omitempty"`
	LoginSelector string                 `json:"loginSelector,omitempty"`
	CustomHeaders map[string]string      `json:"customHeaders,omitempty"`
	CustomParams  map[string]interface{} `json:"customParams,omitempty"`
}
