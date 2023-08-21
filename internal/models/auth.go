package models

type AuthSources struct {
	NullifyToken string `arg:"--nullify-token" help:"nullify api token"`
	GitHubToken  string `arg:"--github-token" help:"github actions job token to exchange for a nullify token"`
}
