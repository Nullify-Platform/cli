package models

import "fmt"

// AuthMethod is a string-based enum describing the authentication method used
// by a DAST scan's AuthConfig.
//
// It is a named string type so it marshals/unmarshals to and from JSON as the
// same strings used on the wire, with no custom (Un)MarshalJSON required. The
// concrete set of methods is owned by the DAST scanner that consumes the auth
// config; the constants below cover the commonly documented methods. Unknown
// values still unmarshal fine — validation only happens where ParseAuthMethod
// is explicitly called at a trust boundary.
type AuthMethod string

const (
	AuthMethodBasic  AuthMethod = "basic"
	AuthMethodBearer AuthMethod = "bearer"
	AuthMethodOAuth  AuthMethod = "oauth"
	AuthMethodForm   AuthMethod = "form"
	AuthMethodHeader AuthMethod = "header"
	AuthMethodCookie AuthMethod = "cookie"
)

// String returns the underlying wire string for the auth method.
func (m AuthMethod) String() string {
	return string(m)
}

// IsValid reports whether the auth method is one of the known values.
func (m AuthMethod) IsValid() bool {
	switch m {
	case AuthMethodBasic, AuthMethodBearer, AuthMethodOAuth, AuthMethodForm, AuthMethodHeader, AuthMethodCookie:
		return true
	default:
		return false
	}
}

// ParseAuthMethod converts a raw string into an AuthMethod, rejecting unknown
// values. Use it at trust boundaries where input must be validated.
func ParseAuthMethod(s string) (AuthMethod, error) {
	m := AuthMethod(s)
	if !m.IsValid() {
		return "", fmt.Errorf("invalid auth method %q", s)
	}
	return m, nil
}
