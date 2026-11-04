// Package findings holds the per-type table of finding operations, and the verbs
// that the CLI and the MCP server both expose from it.
package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
)

// ErrUnknownType is returned for a finding type that is not in the table.
var ErrUnknownType = errors.New("unknown finding type")

// ErrUnreadableResponse is returned for a successful response without the expected
// shape. It must never read as an empty result, because a CI gate would then pass.
var ErrUnreadableResponse = errors.New("unreadable findings response")

// Action calls one finding operation. Operations that take no request body
// ignore body. The result is the JSON response of the API.
type Action func(ctx context.Context, c *api.Client, findingID string, body []byte) (json.RawMessage, error)

// Type holds the operations of one finding type. A nil Action means that the
// API does not support the operation for the type.
type Type struct {
	// APITypes are the values of the /admin/findings "type" filter.
	APITypes []string
	// AllowOnPatch marks a type whose allowlist state is set by one PATCH with
	// the body {allow, reason}. Other types use separate POST routes.
	AllowOnPatch bool
	// AllowlistTypeUnrecorded marks a type for which the server may not record the
	// allowlist type. Bug hunt has no such input. SCA handlers ignore it until
	// monorepo #17588 deploys: remove the mark from the SCA rows when the spec moves
	// past that pull request.
	AllowlistTypeUnrecorded bool

	Get                 Action
	Triage              Action
	CreateTicket        Action
	DeleteTicket        Action
	Allowlist           Action
	Unallowlist         Action
	Archive             Action
	Unarchive           Action
	MarkFalsePositive   Action
	UnmarkFalsePositive Action
	AutofixFix          Action
	AutofixStatus       Action
	AutofixDiff         Action
}

type findingInput[I any] interface {
	*I
	SetFindingID(id string)
}

func read[I any, P findingInput[I], O any](call func(*api.Client, context.Context, I) (*O, error)) Action {
	return func(ctx context.Context, c *api.Client, id string, _ []byte) (json.RawMessage, error) {
		var in I
		P(&in).SetFindingID(id)
		out, err := call(c, ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
}

func write[I any, P findingInput[I], O any](call func(*api.Client, context.Context, I) (*O, error)) Action {
	return func(ctx context.Context, c *api.Client, id string, body []byte) (json.RawMessage, error) {
		var in I
		if len(body) > 0 {
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, err
			}
		}
		P(&in).SetFindingID(id)
		out, err := call(c, ctx, in)
		if err != nil {
			return nil, err
		}
		return json.Marshal(out)
	}
}

// writeRaw adapts a method whose response has no schema in the spec. An empty
// response becomes an empty JSON object, so that every Action returns JSON.
func writeRaw[I any, P findingInput[I]](call func(*api.Client, context.Context, I) ([]byte, error)) Action {
	return func(ctx context.Context, c *api.Client, id string, body []byte) (json.RawMessage, error) {
		var in I
		if len(body) > 0 {
			if err := json.Unmarshal(body, &in); err != nil {
				return nil, err
			}
		}
		P(&in).SetFindingID(id)
		out, err := call(c, ctx, in)
		if err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return json.RawMessage(`{}`), nil
		}
		return out, nil
	}
}

// Types is the table of finding types, keyed by the slug that users pass.
var Types = map[string]Type{
	"sast": {
		APITypes:      []string{"Code"},
		Get:           read((*api.Client).GetSastFindingsFindingId),
		Triage:        read((*api.Client).ListSastFindingsFindingIdTriage),
		CreateTicket:  write((*api.Client).CreateSastFindingsFindingIdTicket),
		DeleteTicket:  read((*api.Client).DeleteSastFindingsFindingIdTicket),
		Allowlist:     write((*api.Client).CreateSastFindingsFindingIdAllowlist),
		Unallowlist:   writeRaw((*api.Client).CreateSastFindingsFindingIdUnallowlist),
		AutofixFix:    write((*api.Client).CreateSastFindingsFindingIdAutofixFix),
		AutofixStatus: read((*api.Client).ListSastFindingsFindingIdAutofixStatus),
		AutofixDiff:   read((*api.Client).ListSastFindingsFindingIdAutofixCacheDiff),
	},
	"sca_dependencies": {
		APITypes:                []string{"Dependencies"},
		AllowlistTypeUnrecorded: true,
		Get:                     read((*api.Client).GetScaDependenciesFindingsFindingId),
		Triage:                  read((*api.Client).ListScaDependenciesFindingsFindingIdTriage),
		CreateTicket:            write((*api.Client).CreateScaDependenciesFindingsFindingIdTicket),
		DeleteTicket:            read((*api.Client).DeleteScaDependenciesFindingsFindingIdTicket),
		Allowlist:               writeRaw((*api.Client).CreateScaDependenciesFindingsFindingIdAllowlist),
		Unallowlist:             writeRaw((*api.Client).CreateScaDependenciesFindingsFindingIdUnallowlist),
		AutofixFix:              write((*api.Client).CreateScaDependenciesFindingsFindingIdAutofixFix),
		AutofixStatus:           read((*api.Client).ListScaDependenciesFindingsFindingIdAutofixStatus),
		AutofixDiff:             read((*api.Client).ListScaDependenciesFindingsFindingIdAutofixCacheDiff),
	},
	"sca_containers": {
		APITypes:                []string{"Containers"},
		AllowlistTypeUnrecorded: true,
		Get:                     read((*api.Client).GetScaContainersFindingsFindingId),
		Triage:                  read((*api.Client).ListScaContainersFindingsFindingIdTriage),
		CreateTicket:            write((*api.Client).CreateScaContainersFindingsFindingIdTicket),
		DeleteTicket:            read((*api.Client).DeleteScaContainersFindingsFindingIdTicket),
		Allowlist:               writeRaw((*api.Client).CreateScaContainersFindingsFindingIdAllowlist),
		Unallowlist:             writeRaw((*api.Client).CreateScaContainersFindingsFindingIdUnallowlist),
		AutofixFix:              write((*api.Client).CreateScaContainersFindingsFindingIdAutofixFix),
		AutofixStatus:           read((*api.Client).ListScaContainersFindingsFindingIdAutofixStatus),
	},
	"secrets": {
		APITypes:     []string{"SecretsCredentials", "SecretsSensitiveData"},
		Get:          read((*api.Client).GetSecretsFindingsFindingId),
		Triage:       read((*api.Client).ListSecretsFindingsFindingIdTriage),
		CreateTicket: write((*api.Client).CreateSecretsFindingsFindingIdTicket),
		DeleteTicket: read((*api.Client).DeleteSecretsFindingsFindingIdTicket),
		Allowlist:    writeRaw((*api.Client).CreateSecretsFindingsFindingIdAllowlist),
		Unallowlist:  writeRaw((*api.Client).CreateSecretsFindingsFindingIdUnallowlist),
	},
	"secrets_sensitive_data": {
		APITypes:     []string{"SecretsSensitiveData"},
		Get:          read((*api.Client).GetSecretsSensitivedataFindingsFindingId),
		Triage:       read((*api.Client).ListSecretsSensitivedataFindingsFindingIdTriage),
		CreateTicket: write((*api.Client).CreateSecretsSensitivedataFindingsFindingIdTicket),
		DeleteTicket: read((*api.Client).DeleteSecretsSensitivedataFindingsFindingIdTicket),
		Allowlist:    writeRaw((*api.Client).CreateSecretsSensitivedataFindingsFindingIdAllowlist),
		Unallowlist:  writeRaw((*api.Client).CreateSecretsSensitivedataFindingsFindingIdUnallowlist),
	},
	"pentest": {
		APITypes:      []string{"Pentest"},
		Get:           read((*api.Client).GetDastPentestFindingsFindingId),
		Triage:        read((*api.Client).ListDastPentestFindingsFindingIdTriage),
		CreateTicket:  write((*api.Client).CreateDastPentestFindingsFindingIdTicket),
		DeleteTicket:  read((*api.Client).DeleteDastPentestFindingsFindingIdTicket),
		Allowlist:     writeRaw((*api.Client).CreateDastPentestFindingsFindingIdAllowlist),
		Unallowlist:   writeRaw((*api.Client).CreateDastPentestFindingsFindingIdUnallowlist),
		AutofixFix:    write((*api.Client).CreateDastPentestFindingsFindingIdAutofixFix),
		AutofixStatus: read((*api.Client).ListDastPentestFindingsFindingIdAutofixStatus),
	},
	"bughunt": {
		APITypes:                []string{"BugHunt"},
		AllowOnPatch:            true,
		AllowlistTypeUnrecorded: true,
		Get:                     read((*api.Client).GetDastBughuntFindingsFindingId),
		Triage:                  read((*api.Client).ListDastBughuntFindingsFindingIdTriage),
		CreateTicket:            write((*api.Client).CreateDastBughuntFindingsFindingIdTicket),
		DeleteTicket:            read((*api.Client).DeleteDastBughuntFindingsFindingIdTicket),
		Allowlist:               write((*api.Client).PatchDastBughuntFindingsFindingIdAllowlist),
		Unallowlist:             write((*api.Client).PatchDastBughuntFindingsFindingIdAllowlist),
	},
	"cspm": {
		APITypes:            []string{"Cloud"},
		Get:                 read((*api.Client).GetCspmFindingsFindingId),
		Triage:              read((*api.Client).ListCspmFindingsFindingIdTriage),
		CreateTicket:        write((*api.Client).CreateCspmFindingsFindingIdTicket),
		DeleteTicket:        read((*api.Client).DeleteCspmFindingsFindingIdTicket),
		Allowlist:           write((*api.Client).CreateCspmFindingsFindingIdAllowlist),
		Unallowlist:         write((*api.Client).CreateCspmFindingsFindingIdUnallowlist),
		Archive:             write((*api.Client).CreateCspmFindingsFindingIdArchive),
		Unarchive:           write((*api.Client).CreateCspmFindingsFindingIdUnarchive),
		MarkFalsePositive:   write((*api.Client).CreateCspmFindingsFindingIdMarkFalsePositive),
		UnmarkFalsePositive: write((*api.Client).CreateCspmFindingsFindingIdUnmarkFalsePositive),
		AutofixFix:          write((*api.Client).CreateCspmFindingsFindingIdAutofixFix),
		AutofixStatus:       read((*api.Client).ListCspmFindingsFindingIdAutofixStatus),
	},
	"scpm": {
		APITypes:            []string{"SupplyChain"},
		Get:                 read((*api.Client).GetScpmFindingsFindingId),
		Triage:              read((*api.Client).ListScpmFindingsFindingIdTriage),
		CreateTicket:        write((*api.Client).CreateScpmFindingsFindingIdTicket),
		DeleteTicket:        read((*api.Client).DeleteScpmFindingsFindingIdTicket),
		Allowlist:           write((*api.Client).CreateScpmFindingsFindingIdAllowlist),
		Unallowlist:         writeRaw((*api.Client).CreateScpmFindingsFindingIdUnallowlist),
		UnmarkFalsePositive: write((*api.Client).CreateScpmFindingsFindingIdUnmarkFalsePositive),
		AutofixFix:          write((*api.Client).CreateScpmFindingsFindingIdAutofixFix),
		AutofixStatus:       read((*api.Client).ListScpmFindingsFindingIdAutofixStatus),
	},
}

var typeAliases = map[string]string{
	"sca":          "sca_dependencies",
	"dependencies": "sca_dependencies",
	"containers":   "sca_containers",
	// The monorepo FindingType names. Its other names are already slugs.
	"secrets_credentials": "SecretsCredentials",
	"dast_bughunt":        "BugHunt",
	"dast_pentest":        "Pentest",
}

// rowTypes maps the "type" value of a listed finding to its slug, so that a row
// from `--type secrets` can go straight to a verb.
var rowTypes = map[string]string{
	"Code":                 "sast",
	"Dependencies":         "sca_dependencies",
	"Containers":           "sca_containers",
	"SecretsCredentials":   "secrets",
	"SecretsSensitiveData": "secrets_sensitive_data",
	"Pentest":              "pentest",
	"BugHunt":              "bughunt",
	"Cloud":                "cspm",
	"SupplyChain":          "scpm",
}

// Names returns the sorted slugs of all finding types.
func Names() []string {
	names := make([]string, 0, len(Types))
	for name := range Types {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NamesWith returns the sorted slugs of the types for which pick reports support.
func NamesWith(pick func(Type) bool) []string {
	var names []string
	for _, name := range Names() {
		if pick(Types[name]) {
			names = append(names, name)
		}
	}
	return names
}

// AcceptedNames returns every sorted name that Lookup resolves to a type for which
// pick reports support: slugs, aliases and the type values of listed findings.
func AcceptedNames(pick func(Type) bool) []string {
	names := NamesWith(pick)
	for _, table := range []map[string]string{typeAliases, rowTypes} {
		for name := range table {
			if t, err := Lookup(name); err == nil && pick(t) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	return names
}

// Lookup resolves a slug, an alias or the type value of a listed finding to its
// type.
func Lookup(name string) (Type, error) {
	if alias, ok := typeAliases[name]; ok {
		name = alias
	}
	if slug, ok := rowTypes[name]; ok {
		name = slug
	}
	t, ok := Types[name]
	if !ok {
		return Type{}, fmt.Errorf("%w %q, valid types: %s", ErrUnknownType, name, strings.Join(Names(), ", "))
	}
	return t, nil
}

// APITypesFor resolves a slug, an alias or a raw API value to the values of the
// /admin/findings "type" filter. "sca" is both SCA types here, because a filter that
// keeps only one would hide the other. A verb acts on one finding, so for a verb
// "sca" is the dependency route (see Lookup).
func APITypesFor(name string) ([]string, error) {
	if name == "sca" {
		return []string{"Dependencies", "Containers"}, nil
	}
	if alias, ok := typeAliases[name]; ok {
		name = alias
	}
	if _, ok := rowTypes[name]; ok {
		return []string{name}, nil
	}
	t, err := Lookup(name)
	if err != nil {
		return nil, err
	}
	return t.APITypes, nil
}

// HasRepository reports whether findings of the API types can belong to a
// repository. Cloud and bug hunt findings have none, so a repository filter removes
// all of them. A repository detected from the working directory must not filter a
// search for them, because that search would then always be empty.
func HasRepository(apiTypes []string) bool {
	return len(apiTypes) == 0 || slices.ContainsFunc(apiTypes, func(t string) bool {
		return t != "Cloud" && t != "BugHunt"
	})
}
