package models

type AuthSources struct {
	NullifyToken string `arg:"--nullify-token" help:"Nullify API token"`
	GitHubToken  string `arg:"--github-token" help:"GitHub actions job token to exchange for a Nullify API token"`
}
