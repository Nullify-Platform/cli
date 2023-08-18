package models

// request provider

type RequestProvider struct {
	GitHubOwnerID int64  `query:"githubOwnerId,omitempty"    json:"githubOwnerId,omitempty"`
	GitHubOwner   string `query:"githubOwner,omitempty"      json:"githubOwner,omitempty"`
}

type RequestDashboardTarget struct {
	GitHubRepository string `query:"githubRepository,omitempty" json:"githubRepository,omitempty"`
}
