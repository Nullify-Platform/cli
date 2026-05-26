package client

import "fmt"

// ScanStatus is a string-based enum describing the status of a DAST external
// scan.
//
// It is a named string type so it marshals/unmarshals to and from JSON as the
// same lowercase strings used on the wire, with no custom (Un)MarshalJSON
// required.
type ScanStatus string

const (
	StatusCompleted ScanStatus = "completed"
)

// String returns the underlying wire string for the scan status.
func (s ScanStatus) String() string {
	return string(s)
}

// IsValid reports whether the scan status is one of the known values.
func (s ScanStatus) IsValid() bool {
	switch s {
	case StatusCompleted:
		return true
	default:
		return false
	}
}

// ParseScanStatus converts a raw string into a ScanStatus, rejecting unknown
// values. Use it at trust boundaries where input must be validated.
func ParseScanStatus(s string) (ScanStatus, error) {
	status := ScanStatus(s)
	if !status.IsValid() {
		return "", fmt.Errorf("invalid scan status %q", s)
	}
	return status, nil
}

// ScanStatusPtr returns a pointer to the given scan status, mirroring the
// String/Int pointer helpers used for optional request fields.
func ScanStatusPtr(value ScanStatus) *ScanStatus {
	return &value
}
