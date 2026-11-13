package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// simRosterPath is the modal sandbox's roster in v1 form, which cmd/derive
// in epack-collector-sandboxes converts from sandboxes/modal/roster.json and
// the refresh workflow commits here.
const simRosterPath = "testdata/simulator/modal.roster.json"

func simBase(t testing.TB) *roster.Roster {
	t.Helper()
	r, err := roster.Load(simRosterPath)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// simMemberRoles and simLogins are Modal's member roles and identity
// providers by the roster's names for them.
var (
	simMemberRoles = map[string]pb.MemberRole{
		"Owner": pb.MemberRole_MEMBER_ROLE_OWNER, "Manager": pb.MemberRole_MEMBER_ROLE_MANAGER, "Member": pb.MemberRole_MEMBER_ROLE_USER,
	}
	simLogins = map[string]pb.IdentityProviderType{
		"github": pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GITHUB,
		"google": pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GOOGLE_OAUTH,
		"saml":   pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_SAML,
	}
)

// simWorkspace is what the roster's workspace block holds beside the
// normalized facts: the workspace's environments, secrets and deployed
// apps, which the collector lists for its details artifact.
type simWorkspace struct {
	environments map[string]struct {
		Default    bool `json:"default"`
		Restricted bool `json:"restricted"`
	}
	secrets map[string]struct {
		Name        string   `json:"name"`
		Environment string   `json:"environment"`
		Keys        []string `json:"keys"`
	}
	deployments map[string]struct {
		Name              string `json:"name"`
		Environment       string `json:"environment"`
		WebEndpoint       bool   `json:"web_endpoint"`
		RequiresProxyAuth bool   `json:"requires_proxy_auth"`
	}
}

func simVendor(r *roster.Roster) simWorkspace {
	var w simWorkspace
	simulate.Extra(r.Workspace.Extra, "environments", &w.environments)
	simulate.Extra(r.Workspace.Extra, "secrets", &w.secrets)
	simulate.Extra(r.Workspace.Extra, "deployments", &w.deployments)
	return w
}

// simEpoch is days days before now, in seconds, as Modal sends times.
func simEpoch(now time.Time, days int) float64 { return epoch(now.AddDate(0, 0, -days)) }

// newModalSim answers every call a run makes for r, at now. Members are the
// roster's enabled accounts. A credential is a proxy auth token when its
// permissions are proxy_auth and a service user when its kind is
// service_user. Modal lists no member's API tokens, so the others answer
// only TokenInfo, for the one the collector signs in with.
func newModalSim(r *roster.Roster, now time.Time) []collectortest.Response {
	w := simVendor(r)
	identity := func(key string) *pb.UserIdentity {
		return pb.UserIdentity_builder{UserId: "us-" + key, Username: key}.Build()
	}
	var caller *pb.UserIdentity
	var tokenName string
	for _, m := range r.Workspace.Credentials {
		var collector bool
		simulate.Extra(m.Extra, "collector", &collector)
		if collector {
			caller, tokenName = identity(m.Owner), m.Key
		}
	}
	owner := ""
	for _, a := range r.Accounts {
		if owner == "" && a.Enabled && slices.Contains(a.Roles, "Owner") {
			owner = a.Key
		}
	}
	out := []collectortest.Response{grpcOK(modal.OpTokenInfo, pb.TokenInfoGetResponse_builder{
		TokenId: kitTokenID, WorkspaceId: kitWorkspaceID, WorkspaceName: kitWorkspaceName, UserIdentity: caller,
		CreatedAt: timestamppb.New(now.AddDate(0, 0, -21)), TokenName: tokenName,
	}.Build())}

	var members []*pb.WorkspaceMembersListItem
	for _, a := range r.Accounts {
		if !a.Enabled {
			continue
		}
		var role pb.MemberRole
		for _, name := range a.Roles {
			role = simMemberRoles[name]
		}
		b := pb.WorkspaceMembersListItem_builder{
			MemberId: "mb-" + a.Key, MemberDisplayname: a.Key, Email: a.Key + "@example.com", UserId: "us-" + a.Key,
			MemberRole: role, JoinedAt: simEpoch(now, 365),
		}
		if len(a.Logins) > 0 {
			b.IdentityProviderType = simLogins[a.Logins[0]]
		}
		if a.SignedInDaysAgo != nil {
			b.LastActiveAt = simEpoch(now, *a.SignedInDaysAgo)
		}
		members = append(members, b.Build())
	}
	out = append(out, grpcOK(modal.OpListMembers, pb.WorkspaceMembersListResponse_builder{Members: members}.Build()))

	var envs []*pb.EnvironmentListItem
	for _, name := range slices.Sorted(maps.Keys(w.environments)) {
		e := w.environments[name]
		b := pb.EnvironmentListItem_builder{
			Name: name, EnvironmentId: "en-" + name, Default: e.Default, IsManaged: e.Restricted, CreatedAt: simEpoch(now, 30),
			EffectiveRole: pb.EnvironmentRole_ENVIRONMENT_ROLE_CONTRIBUTOR.Enum(),
		}
		if e.Restricted {
			b.DefaultMemberRole = pb.EnvironmentRole_ENVIRONMENT_ROLE_NO_ACCESS.Enum()
			out = append(out, grpcFor(modal.OpGetEnvironmentRoles, fmt.Sprintf(`{"environmentId": "en-%s"}`, name), pb.EnvironmentGetRolesResponse_builder{Name: name}.Build()))
		}
		envs = append(envs, b.Build())

		var secrets []*pb.SecretListItem
		for _, key := range slices.Sorted(maps.Keys(w.secrets)) {
			s := w.secrets[key]
			if s.Environment != name {
				continue
			}
			created := simEpoch(now, 20)
			secrets = append(secrets, pb.SecretListItem_builder{
				Label: s.Name, SecretId: "st-" + key, CreatedAt: created,
				Metadata: pb.SecretMetadata_builder{
					Name: s.Name, Keys: s.Keys, EnvironmentName: name,
					CreationInfo: pb.CreationInfo_builder{CreatedAt: created, CreatedBy: owner}.Build(),
				}.Build(),
			}.Build())
		}
		out = append(out, grpcFor(modal.OpListSecrets, fmt.Sprintf(`{"environmentName": %q}`, name),
			pb.SecretListResponse_builder{Items: secrets, EnvironmentName: name}.Build()))

		var apps []*pb.AppListResponse_AppListItem
		for _, key := range slices.Sorted(maps.Keys(w.deployments)) {
			d := w.deployments[key]
			if d.Environment != name {
				continue
			}
			id, fnID := "ap-"+key, "fu-"+key
			created := simEpoch(now, 3)
			fnName, summary := "run", scheduledFunction()
			if d.WebEndpoint {
				fnName, summary = "web", webFunction(d.RequiresProxyAuth)
			}
			meta := pb.AppHandleMetadata_builder{
				Description: d.Name, AppId: id, EnvironmentName: name, Functions: map[string]string{fnName: fnID},
				Lifecycle: pb.AppLifecycle_builder{
					AppState: pb.AppState_APP_STATE_DEPLOYED, CreatedAt: created, CreatedBy: owner, DeployedAt: created, DeployedBy: owner, Version: 1,
				}.Build(),
			}.Build()
			apps = append(apps, pb.AppListResponse_AppListItem_builder{
				AppId: id, Description: d.Name, State: pb.AppState_APP_STATE_DEPLOYED, CreatedAt: created, Name: d.Name, Metadata: meta,
			}.Build())
			out = append(out, grpcFor(modal.OpGetAppInfo, fmt.Sprintf(`{"appId": %q}`, id), pb.AppGetInfoResponse_builder{
				Info: meta, FunctionInfoSummaries: map[string]*pb.AppGetInfoResponse_FunctionInfoSummary{fnID: summary},
			}.Build()))
		}
		out = append(out, grpcFor(modal.OpListApps, fmt.Sprintf(`{"environmentName": %q}`, name), kitAppsIn(apps...)))
	}
	out = append(out, grpcOK(modal.OpListEnvironments, pb.EnvironmentListResponse_builder{Items: envs}.Build()))

	var users []*pb.ServiceUser
	var tokens []*pb.WebhookToken
	for _, m := range r.Workspace.Credentials {
		if !m.Active {
			continue
		}
		var kind, name string
		var scoped []string
		simulate.Extra(m.Extra, "kind", &kind)
		simulate.Extra(m.Extra, "name", &name)
		simulate.Extra(m.Extra, "environments", &scoped)
		name = cmpOr(name, m.Key)
		switch {
		case kind == "service_user":
			b := pb.ServiceUser_builder{Name: name, ServiceUserId: "su-" + m.Key, CreatedBy: m.Owner}
			if m.CreatedDaysAgo != nil {
				b.CreatedAt = simEpoch(now, *m.CreatedDaysAgo)
			}
			if m.LastUsedDaysAgo != nil {
				b.LastUsedAt = simEpoch(now, *m.LastUsedDaysAgo)
			}
			users = append(users, b.Build())
		case m.Permissions == "proxy_auth":
			// Modal reports when every proxy auth token was made. The
			// sandbox roster leaves it out, since the token ages each day.
			b := pb.WebhookToken_builder{TokenId: "wk-" + m.Key, Name: name, Scoped: len(scoped) > 0, CreatedAt: simEpoch(now, 30), CreatedBy: identity(owner)}
			if m.CreatedDaysAgo != nil {
				b.CreatedAt = simEpoch(now, *m.CreatedDaysAgo)
			}
			if len(scoped) > 0 {
				ids := simulate.Each(scoped, func(env string) any { return "en-" + env })
				var envIDs []string
				for _, id := range ids {
					envIDs = append(envIDs, id.(string))
				}
				out = append(out, grpcFor(modal.OpListProxyTokenEnvironments, fmt.Sprintf(`{"tokenId": %q}`, "wk-"+m.Key),
					pb.WebhookTokenEnvironmentListResponse_builder{EnvironmentIds: envIDs}.Build()))
			}
			tokens = append(tokens, b.Build())
		}
	}
	out = append(out, grpcOK(modal.OpListServiceUsers, pb.ServiceUserListResponse_builder{ServiceUsers: users}.Build()))
	return append(out, grpcOK(modal.OpListProxyTokens, pb.WebhookTokenListResponse_builder{Tokens: tokens}.Build()))
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// simTransport answers the collector's calls from responses, as a replay
// does, and reads each request through grpcCodec, so a call made once per
// environment or app gets the answer whose RequestBody its request holds.
type simTransport struct {
	t         *testing.T
	responses []collectortest.Response
}

func (s simTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	op, _ := componentsdk.OperationOf(req.Context())
	var raw []byte
	if req.Body != nil {
		raw, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	decoded, err := grpcCodec{}.DecodeRequest(op.Name, req.Header, raw)
	if err != nil {
		return nil, fmt.Errorf("simulator: %s: %w", op.Name, err)
	}
	for _, r := range s.responses {
		if r.Operation != op.Name || (r.RequestBody != "" && !simHolds(decoded, r.RequestBody)) {
			continue
		}
		header := r.Header.Clone()
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(r.Body)), Request: req}, nil
	}
	s.t.Errorf("simulator: no answer for %s %s", op.Name, decoded)
	return nil, fmt.Errorf("simulator: no answer for %s", op.Name)
}

// simHolds reports whether the JSON object request holds every field of
// want with the same value.
func simHolds(request []byte, want string) bool {
	var got, fields map[string]any
	if json.Unmarshal(request, &got) != nil || json.Unmarshal([]byte(want), &fields) != nil {
		return false
	}
	for k, v := range fields {
		a, _ := json.Marshal(got[k])
		b, _ := json.Marshal(v)
		if !bytes.Equal(a, b) {
			return false
		}
	}
	return true
}

// simHarness runs the collector at the audit level against the simulated
// workspace.
func simHarness(standing simulate.Differences) simulate.Harness {
	return simulate.Harness{
		Simulate: func(r *roster.Roster, _ int) []collectortest.Response { return newModalSim(r, kitNow) },
		Collect: func(t *testing.T, responses []collectortest.Response) componentsdk.InProcessResult {
			return componentsdk.RunInProcess(Spec("test", "simulator"), Run, componentsdk.InProcessOptions{
				Config:    map[string]any{"level": "audit"},
				Secrets:   kitSecrets(),
				Transport: simTransport{t: t, responses: responses},
				Clock:     func() time.Time { return kitNow },
				Seed:      1,
				Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
			})
		},
		Artifacts:  []simulate.Artifact{{Schema: roster.AccessPosture, Path: accessPath}},
		Standing:   standing,
		Coverage:   true,
		Uncompared: simUncompared,
	}
}
