package models

type AuthSources struct {
	NullifyToken string `json:"nullifyToken" arg:"--nullify-token" help:"Nullify API token"`
	GitHubToken  string `json:"githubToken" arg:"--github-token" help:"GitHub actions job token to exchange for a Nullify API token"`
}

type AuthMethod string

const (
	AuthMethodNone    AuthMethod = "none"
	AuthMethodBasic   AuthMethod = "basic"
	AuthMethodBearer  AuthMethod = "bearer"
	AuthMethodSession AuthMethod = "session"
	AuthMethodOAuth   AuthMethod = "oauth"
	AuthMethodSAML    AuthMethod = "saml"
	AuthMethodJWT     AuthMethod = "jwt"
	AuthMethodCustom  AuthMethod = "custom"
)

// AuthConfig represents the authentication configuration for Nullify DAST
type AuthConfig struct {
	// Single user authentication fields
	Method        AuthMethod             `json:"method,omitempty"`
	Username      string                 `json:"username,omitempty"`
	Headers       map[string]string      `json:"headers,omitempty"`
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

	// Multi-user authentication fields
	AuthorizationModel bool       `json:"authorizationModel,omitempty"`
	Users              []UserAuth `json:"users,omitempty"`
}

type UserAuth struct {
	RoleName        string              `json:"roleName"`
	RoleDescription string              `json:"roleDescription,omitempty"`
	AuthConfig      AuthMultiUserConfig `json:"authConfig"`
}

type AuthMultiUserConfig struct {
	Method        AuthMethod             `json:"method,omitempty"`
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
