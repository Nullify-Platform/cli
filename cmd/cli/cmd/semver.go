package cmd

import "strings"

// semver is a parsed semantic version (https://semver.org). Build metadata is
// dropped because it does not affect precedence.
type semver struct {
	core       [3]string // major, minor, patch: digits without leading zeros
	prerelease []string
}

// parseSemver parses MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD], with an optional
// leading v. It reports false for anything else, such as "dev" or a commit SHA.
func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !validIdentifiers(s[i+1:], false) {
			return semver{}, false
		}
		s = s[:i]
	}

	var v semver
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if !validIdentifiers(s[i+1:], true) {
			return semver{}, false
		}
		v.prerelease = strings.Split(s[i+1:], ".")
		s = s[:i]
	}

	core := strings.Split(s, ".")
	if len(core) != 3 {
		return semver{}, false
	}
	for i, n := range core {
		if !semverDigits(n) || hasLeadingZero(n) {
			return semver{}, false
		}
		v.core[i] = n
	}
	return v, true
}

// compareSemver returns -1, 0 or 1 when a has lower, equal or higher
// precedence than b.
func compareSemver(a, b semver) int {
	for i := range a.core {
		if c := compareNumeric(a.core[i], b.core[i]); c != 0 {
			return c
		}
	}
	return comparePrerelease(a.prerelease, b.prerelease)
}

// comparePrerelease orders pre-release identifiers. A release ranks above any
// of its pre-releases.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdentifier(a[i], b[i]); c != 0 {
			return c
		}
	}
	return compareInt(len(a), len(b))
}

// compareIdentifier orders numeric identifiers by value and below
// alphanumeric ones, which are ordered by ASCII.
func compareIdentifier(a, b string) int {
	aNum, bNum := semverDigits(a), semverDigits(b)
	switch {
	case aNum && bNum:
		return compareNumeric(a, b)
	case aNum:
		return -1
	case bNum:
		return 1
	}
	return strings.Compare(a, b)
}

// compareNumeric compares digit strings without leading zeros, of any length.
func compareNumeric(a, b string) int {
	if c := compareInt(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// validIdentifiers checks dot-separated identifiers of [0-9A-Za-z-]. Numeric
// pre-release identifiers must not have leading zeros.
func validIdentifiers(s string, prerelease bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" || strings.Trim(id, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-") != "" {
			return false
		}
		if prerelease && semverDigits(id) && hasLeadingZero(id) {
			return false
		}
	}
	return true
}

func semverDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func hasLeadingZero(s string) bool {
	return len(s) > 1 && s[0] == '0'
}
