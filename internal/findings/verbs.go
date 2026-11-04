package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"
)

// Errors that a verb returns before it calls the API.
var (
	ErrUnsupported          = errors.New("operation is not supported for this finding type")
	ErrFindingIDRequired    = errors.New("a finding ID is required")
	ErrReasonRequired       = errors.New("a reason is required")
	ErrInvalidAllowlistType = errors.New("invalid allowlist type")
	ErrInvalidVerdict       = errors.New("invalid feedback verdict")
)

// AllowlistTypes are the allowlist types that a user can submit. The REST API
// records UserAssumeRisk when the type is absent, so friendly commands and MCP
// tools require an explicit value.
var AllowlistTypes = []string{
	string(models.ModelsAllowlistTypeUserfixed),
	string(models.ModelsAllowlistTypeUserassumerisk),
	string(models.ModelsAllowlistTypeUserfalsepositive),
	string(models.ModelsAllowlistTypeUserother),
}

// FeedbackVerdicts are the verdicts that POST /findings/{id}/feedback accepts.
var FeedbackVerdicts = []string{
	string(models.EndpointsFindingFeedbackVerdictUp),
	string(models.EndpointsFindingFeedbackVerdictDown),
	string(models.EndpointsFindingFeedbackVerdictHelpful),
	string(models.EndpointsFindingFeedbackVerdictWrong),
	string(models.EndpointsFindingFeedbackVerdictNoisy),
	string(models.EndpointsFindingFeedbackVerdictFixGood),
	string(models.EndpointsFindingFeedbackVerdictFixBad),
	string(models.EndpointsFindingFeedbackVerdictWorthFixing),
	string(models.EndpointsFindingFeedbackVerdictExplanationClear),
	string(models.EndpointsFindingFeedbackVerdictExplanationUnclear),
	string(models.EndpointsFindingFeedbackVerdictSeverityRight),
	string(models.EndpointsFindingFeedbackVerdictSeverityWrong),
}

// Params are the inputs that a verb can take in addition to the finding.
type Params struct {
	Reason        string
	AllowlistType string
}

// Verb is one finding operation, exposed as a `nullify findings` subcommand and
// as an MCP tool.
type Verb struct {
	Name        string
	Tool        string
	Description string
	// NeedsReason makes Params.Reason mandatory.
	NeedsReason bool
	// NeedsAllowlistType makes Params.AllowlistType mandatory.
	NeedsAllowlistType bool
	method             func(Type) Action
	body               func(Type, Params) ([]byte, error)
}

// Verbs lists the finding operations in the order that help shows them.
var Verbs = []Verb{
	{
		Name:        "get",
		Tool:        "nullify_get_finding",
		Description: "Get details of a specific finding by type and ID.",
		method:      func(t Type) Action { return t.Get },
	},
	{
		Name:        "triage",
		Tool:        "nullify_get_finding_triage",
		Description: "Get the AI-triage analysis for a finding: the model's assessment of exploitability, severity, and recommended disposition.",
		method:      func(t Type) Action { return t.Triage },
	},
	{
		Name:               "allowlist",
		Tool:               "nullify_allowlist_finding",
		Description:        "Allowlist a finding: suppress it as fixed, accepted risk, false positive, or other. This is how a finding is triaged out of the open queue.",
		NeedsReason:        true,
		NeedsAllowlistType: true,
		method:             func(t Type) Action { return t.Allowlist },
		body:               allowlistBody,
	},
	{
		Name:        "unallowlist",
		Tool:        "nullify_unallowlist_finding",
		Description: "Remove a finding from the allowlist, re-opening it.",
		NeedsReason: true,
		method:      func(t Type) Action { return t.Unallowlist },
		body:        unallowlistBody,
	},
	{
		Name:        "archive",
		Tool:        "nullify_archive_finding",
		Description: "Archive a finding, removing it from the open queue without recording a verdict.",
		method:      func(t Type) Action { return t.Archive },
	},
	{
		Name:        "unarchive",
		Tool:        "nullify_unarchive_finding",
		Description: "Restore an archived finding to the open queue.",
		method:      func(t Type) Action { return t.Unarchive },
	},
	{
		Name:        "mark-false-positive",
		Tool:        "nullify_mark_false_positive",
		Description: "Mark a finding as a false positive.",
		NeedsReason: true,
		method:      func(t Type) Action { return t.MarkFalsePositive },
		body:        falsePositiveBody,
	},
	{
		Name:        "unmark-false-positive",
		Tool:        "nullify_unmark_false_positive",
		Description: "Remove the false positive mark from a finding.",
		method:      func(t Type) Action { return t.UnmarkFalsePositive },
	},
	{
		Name:        "create-ticket",
		Tool:        "nullify_create_ticket",
		Description: "Create a ticket (e.g. Jira, GitHub issue) for a finding.",
		method:      func(t Type) Action { return t.CreateTicket },
	},
	{
		Name:        "delete-ticket",
		Tool:        "nullify_delete_ticket",
		Description: "Delete the ticket of a finding.",
		method:      func(t Type) Action { return t.DeleteTicket },
	},
}

// Run calls the verb for one finding after it validates the inputs.
func (v Verb) Run(ctx context.Context, c *api.Client, typeName, findingID string, params Params) (json.RawMessage, error) {
	t, err := Lookup(typeName)
	if err != nil {
		return nil, err
	}

	action := v.method(t)
	if action == nil {
		return nil, fmt.Errorf("%s of type %q: %w, supported types: %s", v.Name, typeName, ErrUnsupported, strings.Join(v.Types(), ", "))
	}
	if findingID == "" {
		return nil, ErrFindingIDRequired
	}
	if v.NeedsReason && strings.TrimSpace(params.Reason) == "" {
		return nil, ErrReasonRequired
	}
	if v.NeedsAllowlistType && !slices.Contains(AllowlistTypes, params.AllowlistType) {
		return nil, fmt.Errorf("%w %q, valid types: %s", ErrInvalidAllowlistType, params.AllowlistType, strings.Join(AllowlistTypes, ", "))
	}

	var body []byte
	if v.body != nil {
		body, err = v.body(t, params)
		if err != nil {
			return nil, err
		}
	}
	return action(ctx, c, findingID, body)
}

// Types returns the finding types that support the verb.
func (v Verb) Types() []string {
	return NamesWith(func(t Type) bool { return v.method(t) != nil })
}

func allowlistBody(t Type, p Params) ([]byte, error) {
	if t.AllowOnPatch {
		return json.Marshal(map[string]any{"allow": true, "reason": p.Reason})
	}
	return json.Marshal(map[string]string{"allowlistReason": p.Reason, "allowlistType": p.AllowlistType})
}

func unallowlistBody(t Type, p Params) ([]byte, error) {
	if t.AllowOnPatch {
		return json.Marshal(map[string]any{"allow": false, "reason": p.Reason})
	}
	return json.Marshal(map[string]string{"unallowlistReason": p.Reason})
}

func falsePositiveBody(_ Type, p Params) ([]byte, error) {
	return json.Marshal(map[string]string{"falsePositiveReason": p.Reason})
}

// SubmitFeedback records a verdict on a finding of any type. It never changes
// the finding.
func SubmitFeedback(ctx context.Context, c *api.Client, findingID, verdict, comment string) (json.RawMessage, error) {
	if findingID == "" {
		return nil, ErrFindingIDRequired
	}
	if !slices.Contains(FeedbackVerdicts, verdict) {
		return nil, fmt.Errorf("%w %q, valid verdicts: %s", ErrInvalidVerdict, verdict, strings.Join(FeedbackVerdicts, ", "))
	}

	in := api.CreateFindingsFindingIdFeedbackInput{
		FindingID: findingID,
		Verdict:   models.EndpointsFindingFeedbackVerdict(verdict),
	}
	if comment != "" {
		in.CommentText = &comment
	}
	out, err := c.CreateFindingsFindingIdFeedback(ctx, in)
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// ListFeedback returns the feedback recorded on a finding.
func ListFeedback(ctx context.Context, c *api.Client, findingID string) (json.RawMessage, error) {
	if findingID == "" {
		return nil, ErrFindingIDRequired
	}
	out, err := c.ListFindingsFindingIdFeedback(ctx, api.ListFindingsFindingIdFeedbackInput{FindingID: findingID})
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}
