package models

type AuthSources struct {
	NullifyToken string `json:"nullifyToken" arg:"--nullify-token" help:"Nullify API token"`
	GitHubToken  string `json:"githubToken" arg:"--github-token" help:"GitHub actions job token to exchange for a Nullify API token"`
}

type AuthConfig struct {
	Headers map[string]string `json:"headers"`
}
