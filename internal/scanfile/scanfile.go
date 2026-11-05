// Package scanfile detects secrets in local files and editor buffers.
package scanfile

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	detectorClassSecret       = "Secret"
	cweHardcodedCredentials   = "CWE-798"
	severityHigh              = "high"
	messagePrefix             = "Hardcoded secret detected: "
	maxFindingsPerFileDefault = 200
)

// NormalizedFinding describes a secret without its value. Lines and UTF-16
// columns are 1-based. EndColumn includes the last character of the secret.
type NormalizedFinding struct {
	DetectorClass string `json:"detectorClass"`
	Severity      string `json:"severity"`
	File          string `json:"file"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
	StartColumn   int    `json:"startColumn"`
	EndColumn     int    `json:"endColumn"`
	CWE           string `json:"cwe"`
	Message       string `json:"message"`
	Fingerprint   string `json:"fingerprint"`
}

// ScanContent scans a file or buffer for secrets without network access.
// filePath labels each finding and selects path exclusions. repository is
// part of the fingerprint. Rule names can differ from platform secret types,
// so fingerprints do not guarantee correlation with platform findings.
func ScanContent(content []byte, filePath string, repository string) []NormalizedFinding {
	findings := make([]NormalizedFinding, 0)
	if isLockfilePath(filePath) {
		return findings
	}

	text := string(content)
	lines := strings.Split(text, "\n")
	lineOffsets := make([]int, len(lines))
	lowerLines := make([]string, len(lines))
	for i, line := range lines {
		lowerLines[i] = strings.ToLower(line)
		if i > 0 {
			lineOffsets[i] = lineOffsets[i-1] + len(lines[i-1]) + 1
		}
	}

	for _, rule := range rules() {
		segments := lines
		lowerSegments := lowerLines
		if rule.Multiline {
			segments = []string{text}
			lowerSegments = []string{strings.ToLower(text)}
		}

		ruleFindings := 0
		for segmentIdx, segment := range segments {
			if ruleFindings >= maxFindingsPerFileDefault {
				break
			}
			if !keywordsPresent(lowerSegments[segmentIdx], rule.Keywords) {
				continue
			}

			for _, match := range rule.Regex.FindAllStringSubmatchIndex(segment, -1) {
				startByte, endByte := secretSpan(match)
				secret := segment[startByte:endByte]
				if isTestOrPlaceholder(secret) {
					continue
				}
				if rule.MinEntropy > 0 && !isHighConfidenceSecret(secret) && shannonEntropy(secret) < rule.MinEntropy {
					continue
				}

				startByte += lineOffsets[segmentIdx]
				endByte += lineOffsets[segmentIdx]
				startLine := sort.Search(len(lineOffsets), func(i int) bool {
					return lineOffsets[i] > startByte
				}) - 1
				endLine := sort.Search(len(lineOffsets), func(i int) bool {
					return lineOffsets[i] >= endByte
				}) - 1

				findings = append(findings, NormalizedFinding{
					DetectorClass: detectorClassSecret,
					Severity:      severityHigh,
					File:          filePath,
					StartLine:     startLine + 1,
					EndLine:       endLine + 1,
					StartColumn:   utf16Length(text[lineOffsets[startLine]:startByte]) + 1,
					EndColumn:     utf16Length(text[lineOffsets[endLine]:endByte]),
					CWE:           cweHardcodedCredentials,
					Message:       messagePrefix + rule.Title(),
					Fingerprint:   fingerprint(repository, filePath, startLine+1, rule.Title()),
				})
				ruleFindings++
				if ruleFindings >= maxFindingsPerFileDefault {
					break
				}
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].StartLine < findings[j].StartLine
	})
	if len(findings) > maxFindingsPerFileDefault {
		findings = findings[:maxFindingsPerFileDefault]
	}
	return findings
}

func utf16Length(s string) int {
	length := 0
	for _, r := range s {
		length += utf16.RuneLen(r)
	}
	return length
}

func secretSpan(match []int) (start, end int) {
	for i := 2; i+1 < len(match); i += 2 {
		if match[i] >= 0 && match[i+1] >= 0 {
			return match[i], match[i+1]
		}
	}
	return match[0], match[1]
}

func keywordsPresent(lowerLine string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, kw := range keywords {
		if strings.Contains(lowerLine, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func fingerprint(repository, file string, startLine int, secretType string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"secret",
		repository,
		file,
		strconv.Itoa(startLine),
		secretType,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}
