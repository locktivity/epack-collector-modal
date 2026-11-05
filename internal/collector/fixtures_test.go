package collector

import (
	"encoding/binary"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/protobuf/proto"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// The kit's workspace and token. Its members, environments, and workloads
// match the sandbox, a Starter workspace kept with known settings. It also
// has what only the Team plan has: a restricted environment, service users,
// and a scoped proxy auth token.
const (
	kitWorkspaceID   = "ac-0123456789abcdefghijkl"
	kitWorkspaceName = "kit-workspace"
	kitTokenID       = "ak-kittoken0123456789abcd"
	kitTokenSecret   = "as-kitsecret0123456789abcdefghij"
	kitManagerUserID = "us-kitmanager0123456789"
	kitProdEnvID     = "en-kitprod0123456789abcd"
)

func kitSecrets() map[string]string {
	return map[string]string{tokenIDEnv: kitTokenID, tokenSecretEnv: kitTokenSecret}
}

// grpcBody frames m as Modal sends a successful answer.
func grpcBody(m proto.Message) string {
	payload, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	frame := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	return string(append(frame, payload...))
}

// grpcOK answers op with m.
func grpcOK(op string, m proto.Message) collectortest.Response {
	return collectortest.Response{Operation: op, Method: http.MethodPost, Header: http.Header{"Content-Type": {"application/grpc"}}, Body: grpcBody(m)}
}

// grpcFor answers op with m for each request whose body holds request,
// such as {"appId": "ap-kitpublic"}. The calls made once per environment or
// app each get their own answer this way, whatever order they come in.
func grpcFor(op, request string, m proto.Message) collectortest.Response {
	r := grpcOK(op, m)
	r.RequestBody = request
	return r
}

// grpcError answers op as Modal answers a failed call: HTTP 200 with the
// gRPC status in the headers and no body.
func grpcError(op string, status int, message string) collectortest.Response {
	return collectortest.Response{Operation: op, Method: http.MethodPost, Header: http.Header{
		"Content-Type": {"application/grpc"},
		"Grpc-Status":  {strconv.Itoa(status)},
		"Grpc-Message": {message},
	}}
}

// epoch is t in seconds, as Modal sends times.
func epoch(t time.Time) float64 {
	return float64(t.Unix())
}

func kitTokenInfo() *pb.TokenInfoGetResponse {
	return pb.TokenInfoGetResponse_builder{
		TokenId:       kitTokenID,
		WorkspaceId:   kitWorkspaceID,
		WorkspaceName: kitWorkspaceName,
		UserIdentity:  pb.UserIdentity_builder{UserId: kitManagerUserID, Username: "kit-manager"}.Build(),
	}.Build()
}

func kitMembers() *pb.WorkspaceMembersListResponse {
	member := func(name, email string, role pb.MemberRole, provider pb.IdentityProviderType, joined, active time.Time) *pb.WorkspaceMembersListItem {
		b := pb.WorkspaceMembersListItem_builder{
			MemberId: "mb-" + name, MemberDisplayname: name, Email: email, UserId: "us-" + name,
			MemberRole: role, IdentityProviderType: provider, JoinedAt: epoch(joined),
		}
		if !active.IsZero() {
			b.LastActiveAt = epoch(active)
		}
		return b.Build()
	}
	return pb.WorkspaceMembersListResponse_builder{Members: []*pb.WorkspaceMembersListItem{
		member("kit-owner", "owner@example.com", pb.MemberRole_MEMBER_ROLE_OWNER, pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GITHUB, kitNow.AddDate(0, -2, 0), kitNow.Add(-time.Hour)),
		member("kit-member", "Member@example.com", pb.MemberRole_MEMBER_ROLE_USER, pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GOOGLE_OAUTH, kitNow.AddDate(0, -1, 0), time.Time{}),
		member("kit-manager", "manager@example.com", pb.MemberRole_MEMBER_ROLE_MANAGER, pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GOOGLE_OAUTH, kitNow.AddDate(0, -1, 0), kitNow.AddDate(0, 0, -100)),
	}}.Build()
}

func kitEnvironments() *pb.EnvironmentListResponse {
	return pb.EnvironmentListResponse_builder{Items: []*pb.EnvironmentListItem{
		pb.EnvironmentListItem_builder{Name: "main", EnvironmentId: "en-kitmain0123456789abcd", Default: true, CreatedAt: epoch(kitNow.AddDate(0, -2, 0))}.Build(),
		pb.EnvironmentListItem_builder{
			Name: "prod", EnvironmentId: kitProdEnvID, IsManaged: true, CreatedAt: epoch(kitNow.AddDate(0, 0, -20)),
			DefaultMemberRole:             pb.EnvironmentRole_ENVIRONMENT_ROLE_NO_ACCESS.Enum(),
			BlockUnauthenticatedResources: proto.Bool(true),
		}.Build(),
		pb.EnvironmentListItem_builder{Name: "dev", EnvironmentId: "en-kitdev0123456789abcde", CreatedAt: epoch(kitNow.AddDate(0, 0, -20)), BlockUnauthenticatedResources: proto.Bool(false)}.Build(),
	}}.Build()
}

func kitProdRoles() *pb.EnvironmentGetRolesResponse {
	return pb.EnvironmentGetRolesResponse_builder{Name: "prod", PrincipalRoles: []*pb.EnvironmentGetRolesResponse_Principal{
		pb.EnvironmentGetRolesResponse_Principal_builder{UserId: "us-kit-member", Email: "member@example.com", Role: pb.EnvironmentRole_ENVIRONMENT_ROLE_VIEWER, HasRoleAssignment: proto.Bool(true), InheritsDefaultMemberRole: proto.Bool(false)}.Build(),
		pb.EnvironmentGetRolesResponse_Principal_builder{UserId: "us-kit-owner", Email: "owner@example.com", Role: pb.EnvironmentRole_ENVIRONMENT_ROLE_CONTRIBUTOR, InheritsDefaultMemberRole: proto.Bool(true)}.Build(),
		pb.EnvironmentGetRolesResponse_Principal_builder{ServiceUserId: "su-kitdeployer", ServiceUserName: "ci-deployer", Role: pb.EnvironmentRole_ENVIRONMENT_ROLE_CONTRIBUTOR, HasRoleAssignment: proto.Bool(true)}.Build(),
	}}.Build()
}

func kitServiceUsers() *pb.ServiceUserListResponse {
	return pb.ServiceUserListResponse_builder{ServiceUsers: []*pb.ServiceUser{
		pb.ServiceUser_builder{Name: "unused-bot", ServiceUserId: "su-kitunused", CreatedBy: "kit-owner", CreatedAt: epoch(kitNow.AddDate(0, 0, -10))}.Build(),
		pb.ServiceUser_builder{Name: "ci-deployer", ServiceUserId: "su-kitdeployer", CreatedBy: "kit-manager", CreatedAt: epoch(kitNow.AddDate(0, 0, -10)), LastUsedAt: epoch(kitNow.Add(-2 * time.Hour))}.Build(),
	}}.Build()
}

func kitProxyTokens() *pb.WebhookTokenListResponse {
	return pb.WebhookTokenListResponse_builder{Tokens: []*pb.WebhookToken{
		pb.WebhookToken_builder{TokenId: "wk-kitcaller", Name: "sandbox-caller", CreatedAt: epoch(kitNow.AddDate(0, 0, -120)), CreatedBy: pb.UserIdentity_builder{UserId: "us-kit-owner", Username: "kit-owner"}.Build()}.Build(),
		pb.WebhookToken_builder{TokenId: "wk-kitprod", Name: "prod-caller", Scoped: true, CreatedAt: epoch(kitNow.AddDate(0, 0, -5)), CreatedBy: pb.UserIdentity_builder{UserId: "us-kit-manager", Username: "kit-manager"}.Build()}.Build(),
	}}.Build()
}

func kitProdCallerEnvironments() *pb.WebhookTokenEnvironmentListResponse {
	return pb.WebhookTokenEnvironmentListResponse_builder{EnvironmentIds: []string{kitProdEnvID}}.Build()
}

func kitSecret(name, env string, keys []string, created, used time.Time) *pb.SecretListItem {
	b := pb.SecretListItem_builder{
		Label: name, SecretId: "st-" + name, EnvironmentName: env,
		Metadata: pb.SecretMetadata_builder{
			Name: name, Keys: keys, EnvironmentName: env,
			CreationInfo: pb.CreationInfo_builder{CreatedAt: epoch(created), CreatedBy: "kit-owner"}.Build(),
		}.Build(),
	}
	if !used.IsZero() {
		b.LastUsedAt = epoch(used)
	}
	return b.Build()
}

func kitSecretsIn(items ...*pb.SecretListItem) *pb.SecretListResponse {
	return pb.SecretListResponse_builder{Items: items}.Build()
}

func kitApp(name, id string, state pb.AppState) *pb.AppListResponse_AppListItem {
	return pb.AppListResponse_AppListItem_builder{Name: name, AppId: id, State: state, CreatedAt: epoch(kitNow.AddDate(0, 0, -3))}.Build()
}

func kitAppsIn(apps ...*pb.AppListResponse_AppListItem) *pb.AppListResponse {
	return pb.AppListResponse_builder{Apps: apps}.Build()
}

// kitFunctions is an app's function summaries, keyed by function name.
func kitFunctions(fns map[string]*pb.AppGetInfoResponse_FunctionInfoSummary) *pb.AppGetInfoResponse {
	return pb.AppGetInfoResponse_builder{FunctionInfoSummaries: fns}.Build()
}

func webFunction(proxyAuth bool) *pb.AppGetInfoResponse_FunctionInfoSummary {
	return pb.AppGetInfoResponse_FunctionInfoSummary_builder{WebFunction: true, RequiresProxyAuth: proto.Bool(proxyAuth)}.Build()
}

func scheduledFunction() *pb.AppGetInfoResponse_FunctionInfoSummary {
	return pb.AppGetInfoResponse_FunctionInfoSummary_builder{Schedule: &pb.Schedule{}}.Build()
}

// withResponses returns responses with each answer to an operation in
// answers replaced by those answers.
func withResponses(responses []collectortest.Response, answers ...collectortest.Response) []collectortest.Response {
	replaced := map[string]bool{}
	for _, a := range answers {
		replaced[a.Operation] = true
	}
	out := slices.DeleteFunc(slices.Clone(responses), func(r collectortest.Response) bool { return replaced[r.Operation] })
	return append(out, answers...)
}

// kitWorkspace answers every call of a clean run.
func kitWorkspace() []collectortest.Response {
	return []collectortest.Response{
		grpcOK(modal.OpTokenInfo, kitTokenInfo()),
		grpcOK(modal.OpListMembers, kitMembers()),
		grpcOK(modal.OpListEnvironments, kitEnvironments()),
		grpcOK(modal.OpGetEnvironmentRoles, kitProdRoles()),
		grpcOK(modal.OpListServiceUsers, kitServiceUsers()),
		grpcOK(modal.OpListProxyTokens, kitProxyTokens()),
		grpcOK(modal.OpListProxyTokenEnvironments, kitProdCallerEnvironments()),
		grpcFor(modal.OpListSecrets, `{"environmentName": "dev"}`, kitSecretsIn(kitSecret("api-key", "dev", []string{"API_KEY"}, kitNow.AddDate(0, 0, -3), time.Time{}))),
		grpcFor(modal.OpListSecrets, `{"environmentName": "main"}`, kitSecretsIn()),
		grpcFor(modal.OpListSecrets, `{"environmentName": "prod"}`, kitSecretsIn(
			kitSecret("stale-token", "prod", []string{"TOKEN"}, kitNow.AddDate(0, 0, -3), time.Time{}),
			kitSecret("db-credentials", "prod", []string{"DB_PASSWORD", "DB_USER"}, kitNow.AddDate(0, 0, -3), kitNow.Add(-7*time.Hour)),
		)),
		grpcFor(modal.OpListApps, `{"environmentName": "dev"}`, kitAppsIn(kitApp("sandbox-public-api", "ap-kitpublic", pb.AppState_APP_STATE_DEPLOYED))),
		grpcFor(modal.OpGetAppInfo, `{"appId": "ap-kitpublic"}`, kitFunctions(map[string]*pb.AppGetInfoResponse_FunctionInfoSummary{"web": webFunction(false)})),
		grpcFor(modal.OpListApps, `{"environmentName": "main"}`, kitAppsIn()),
		grpcFor(modal.OpListApps, `{"environmentName": "prod"}`, kitAppsIn(
			kitApp("sandbox-private-api", "ap-kitprivate", pb.AppState_APP_STATE_DEPLOYED),
			kitApp("sandbox-nightly-job", "ap-kitnightly", pb.AppState_APP_STATE_DEPLOYED),
			kitApp("old-job", "ap-kitold", pb.AppState_APP_STATE_STOPPED),
		)),
		grpcFor(modal.OpGetAppInfo, `{"appId": "ap-kitprivate"}`, kitFunctions(map[string]*pb.AppGetInfoResponse_FunctionInfoSummary{"web": webFunction(true)})),
		grpcFor(modal.OpGetAppInfo, `{"appId": "ap-kitnightly"}`, kitFunctions(map[string]*pb.AppGetInfoResponse_FunctionInfoSummary{"run": scheduledFunction()})),
	}
}
