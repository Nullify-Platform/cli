package ci

// Registry enumerates every known CI provider in priority order. First
// match wins. Local MUST be last — it always returns true from Detect()
// so the CLI still works when run from a developer's laptop.
//
// When adding a new provider:
//  1. Implement Provider in a new file under this package.
//  2. Define its Platform constant in ci.go and return it from Platform().
//  3. Append it to the list below (before Local).

// Default returns the full list of providers in detection priority.
// Exposed as a constructor (not a package-level var) so tests can build
// a truncated list without touching shared state.
func Default() []Provider {
	return []Provider{
		NewGitHubActions(),
		NewGitLabCI(),
		NewCircleCI(),
		NewBitbucketPipelines(),
		NewJenkins(),
		NewAzureDevOps(),
		NewGoogleCloudBuild(),
		NewAWSCodeBuild(),
		NewLocal(), // always last — always matches
	}
}

// Detect walks providers in order and returns the first one whose
// Detect() matches. Returns ErrNoProvider only if the caller passed a
// custom list without Local.
func Detect(providers []Provider) (Provider, error) {
	for _, p := range providers {
		if p.Detect() {
			return p, nil
		}
	}
	return nil, ErrNoProvider
}
