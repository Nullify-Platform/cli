package ci

import "testing"

// signatureEnvs are every env var any provider's Detect() keys on. Tests
// clear them all, then set only the ones under test, so the host's own
// environment can't leak into detection.
var signatureEnvs = []string{
	"GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BITBUCKET_BUILD_NUMBER",
	"JENKINS_URL", "TF_BUILD", "BUILD_ID", "PROJECT_ID", "CODEBUILD_BUILD_ID",
}

func clearSignatureEnvs(t *testing.T) {
	t.Helper()
	for _, k := range signatureEnvs {
		t.Setenv(k, "")
	}
}

func TestDetectPriority(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want Platform
	}{
		{"github", map[string]string{"GITHUB_ACTIONS": "true"}, PlatformGitHubActions},
		{"gitlab", map[string]string{"GITLAB_CI": "true"}, PlatformGitLabCI},
		{"circleci", map[string]string{"CIRCLECI": "true"}, PlatformCircleCI},
		{"bitbucket", map[string]string{"BITBUCKET_BUILD_NUMBER": "42"}, PlatformBitbucketPipelines},
		{"jenkins", map[string]string{"JENKINS_URL": "https://ci"}, PlatformJenkins},
		{"azure", map[string]string{"TF_BUILD": "True"}, PlatformAzureDevOps},
		{"gcb", map[string]string{"BUILD_ID": "1", "PROJECT_ID": "p"}, PlatformGoogleCloudBuild},
		{"aws", map[string]string{"CODEBUILD_BUILD_ID": "x"}, PlatformAWSCodeBuild},
		{"fallback", map[string]string{}, PlatformOther},
		// GitHub wins when several signatures match (priority order).
		{"github_over_gitlab", map[string]string{"GITHUB_ACTIONS": "true", "GITLAB_CI": "true"}, PlatformGitHubActions},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearSignatureEnvs(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			p, err := Detect(Default())
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if p.Platform() != c.want {
				t.Errorf("Platform() = %q, want %q", p.Platform(), c.want)
			}
		})
	}
}

func TestDetect_NoLocalFallback(t *testing.T) {
	clearSignatureEnvs(t)
	if _, err := Detect([]Provider{NewGitHubActions()}); err != ErrNoProvider {
		t.Fatalf("err = %v, want ErrNoProvider", err)
	}
}

func TestLocalAlwaysLast(t *testing.T) {
	list := Default()
	if _, ok := list[len(list)-1].(*Local); !ok {
		t.Fatalf("last provider = %T, want *Local", list[len(list)-1])
	}
}

func TestRepoSlug(t *testing.T) {
	cases := []struct {
		name        string
		provider    Provider
		env         map[string]string
		owner, repo string
		ok          bool
	}{
		{"github", NewGitHubActions(), map[string]string{"GITHUB_REPOSITORY": "octocat/hello"}, "octocat", "hello", true},
		{"gitlab_nested", NewGitLabCI(), map[string]string{"CI_PROJECT_PATH": "group/sub/proj"}, "group/sub", "proj", true},
		{"circleci", NewCircleCI(), map[string]string{"CIRCLE_PROJECT_USERNAME": "acme", "CIRCLE_PROJECT_REPONAME": "widget"}, "acme", "widget", true},
		{"aws_https", NewAWSCodeBuild(), map[string]string{"CODEBUILD_SOURCE_REPO_URL": "https://github.com/acme/widget.git"}, "acme", "widget", true},
		{"aws_ssh", NewAWSCodeBuild(), map[string]string{"CODEBUILD_SOURCE_REPO_URL": "git@github.com:acme/widget.git"}, "acme", "widget", true},
		{"github_missing", NewGitHubActions(), map[string]string{"GITHUB_REPOSITORY": ""}, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			owner, repo, ok := c.provider.RepoSlug()
			if ok != c.ok || owner != c.owner || repo != c.repo {
				t.Errorf("RepoSlug() = (%q, %q, %v), want (%q, %q, %v)", owner, repo, ok, c.owner, c.repo, c.ok)
			}
		})
	}
}

func TestPRNumber(t *testing.T) {
	cases := []struct {
		name     string
		provider Provider
		env      map[string]string
		want     int
		ok       bool
	}{
		{"github_pr", NewGitHubActions(), map[string]string{"GITHUB_REF": "refs/pull/123/merge"}, 123, true},
		{"github_push", NewGitHubActions(), map[string]string{"GITHUB_REF": "refs/heads/main"}, 0, false},
		{"circle_url", NewCircleCI(), map[string]string{"CIRCLE_PULL_REQUEST": "https://github.com/org/repo/pull/77"}, 77, true},
		{"gitlab_iid", NewGitLabCI(), map[string]string{"CI_MERGE_REQUEST_IID": "9"}, 9, true},
		{"aws_trigger", NewAWSCodeBuild(), map[string]string{"CODEBUILD_WEBHOOK_TRIGGER": "pr/55"}, 55, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			n, ok := c.provider.PRNumber()
			if n != c.want || ok != c.ok {
				t.Errorf("PRNumber() = (%d, %v), want (%d, %v)", n, ok, c.want, c.ok)
			}
		})
	}
}

func TestEnrichHeaderStampsProvider(t *testing.T) {
	clearSignatureEnvs(t)
	h := make(map[string][]string)
	NewLocal().EnrichHeader(h)
	if got := h["X-Nullify-Ci-Provider"]; len(got) != 1 || got[0] != string(PlatformOther) {
		t.Fatalf("X-Nullify-CI-Provider = %v, want [%q]", got, PlatformOther)
	}
}
