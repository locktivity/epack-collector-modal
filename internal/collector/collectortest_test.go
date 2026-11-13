package collector

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
	"google.golang.org/protobuf/proto"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// kitNow is the time the hand-built scenarios run at.
var kitNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// kitEmptyList says why a list Modal leaves out is an empty one.
const kitEmptyList = "Protobuf sends nothing for an empty repeated field, so an empty list arrives left out, as the sandbox recording's empty lists do."

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/modal.collector-result.json"

// kitSteps are a run's steps in order.
var kitSteps = []string{"sign_in", "members", "environments", "tokens", "workloads"}

// kitAccessSteps are the steps of a run that collects only the
// access-posture artifact. A workspace with a Member lists the environments
// for it, to tell whether a restricted one limits the Member.
var kitAccessSteps = []string{"sign_in", "members", "environments", "tokens"}

// TestCollectorKit runs the collector against the scenarios below and the
// one recorded from the sandbox, then injects faults into each operation's
// calls and checks the output against the schema, every collection level,
// and the credential and sensitivity rules. grpcCodec lets the kit read
// Modal's protobuf bodies as JSON. Protobuf sends nothing for a field at its
// zero value, so to the field-faults check a dropped field and a zero one
// look the same. The omissions declare the fields whose zero value has a
// meaning, each with its source. Modal's messages are in
// modal_proto/api.proto in modal-labs/modal-client.
func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:        Spec("test", "collectortest"),
		Run:         Run,
		Config:      map[string]any{"level": "internal"},
		Secrets:     kitSecrets(),
		Clock:       kitNow,
		FieldFaults: true,
		Populations: []collectortest.Population{
			{Operation: modal.OpListServiceUsers, List: "/serviceUsers", Reason: "Only the Team and Enterprise plans have service users, as docs/overview.md says; the sandbox recording, a Starter workspace, lists none."},
			{Operation: modal.OpListProxyTokens, List: "/tokens", Reason: "A workspace has no proxy auth tokens until one is created in its settings or with the CLI: https://modal.com/docs/guide/webhook-proxy-auth"},
			{Operation: modal.OpListSecrets, List: "/items", Reason: "An environment can hold no secrets; the sandbox recording's main environment lists none."},
			{Operation: modal.OpListApps, List: "/apps", Reason: "An environment can hold no apps; the sandbox recording's main environment lists none."},
		},
		Omissions: []collectortest.Omission{
			{Operation: modal.OpListServiceUsers, Field: "/serviceUsers", Reason: kitEmptyList},
			{Operation: modal.OpListProxyTokens, Field: "/tokens", Reason: kitEmptyList},
			{Operation: modal.OpListSecrets, Field: "/items", Reason: kitEmptyList},
			{Operation: modal.OpListApps, Field: "/apps", Reason: kitEmptyList},
			{Operation: modal.OpListMembers, Field: "/members/*/lastActiveAt", Reason: "WorkspaceMembersListItem.last_active_at is a proto3 double, sent only when not 0, and Modal's SDK reads 0 as no activity (members.list in py/modal/_workspace.py). The sandbox recording's Member has none."},
			{Operation: modal.OpListMembers, Field: "/members/*/identityProviderType", Reason: `The schema's other_count "Counts the listed members whose identity provider type is missing or is not GitHub, Google OAuth, or SAML." (docs/schema/v1.0.0.json), so a member with none signs in another way, and not with SAML SSO.`},
			{Operation: modal.OpListServiceUsers, Field: "/serviceUsers/*/lastUsedAt", Reason: "ServiceUser.last_used_at is a proto3 double, sent only when not 0, and Modal's SDK reads 0 as never used (ServiceUserInfo._from_proto in py/modal/types.py)."},
			{Operation: modal.OpListSecrets, Field: "/items/*/lastUsedAt", Reason: "SecretListItem.last_used_at is a proto3 double, sent only when not 0, and modal secret list shows 0 as never used (py/modal/cli/secret.py). The sandbox recording's unused secrets have none."},
			{Operation: modal.OpListProxyTokens, Field: "/tokens/*/scoped", Reason: "WebhookToken.scoped is a proto3 bool with no presence, sent only when true; the sandbox recording's Starter token has none."},
			{Operation: modal.OpListEnvironments, Field: "/items/*/default", Reason: "EnvironmentListItem.default is a proto3 bool with no presence, sent only when true; the sandbox recording sends it for main alone."},
			{Operation: modal.OpListEnvironments, Field: "/items/*/isManaged", Reason: "EnvironmentListItem.is_managed is a proto3 bool with no presence, sent only for a restricted environment; the sandbox recording, with no restricted environment, has none."},
			{Operation: modal.OpListEnvironments, Field: "/items/*/blockUnauthenticatedResources", Reason: "An environment with no setting of its own has no block_unauthenticated_resources and follows the workspace default, which Modal doesn't report, as docs/overview.md says. The sandbox recording's environments have none."},
			{Operation: modal.OpGetAppInfo, Field: "/functionInfoSummaries/*/webFunction", Reason: "FunctionInfoSummary.web_function is a proto3 bool with no presence, sent only for a web function; the sandbox recording's scheduled function has none."},
			{Operation: modal.OpGetAppInfo, Field: "/functionInfoSummaries/*/requiresProxyAuth", Reason: "Web functions are public by default, and need a proxy auth token only when requires_proxy_auth=True is set: https://modal.com/docs/guide/webhook-proxy-auth"},
			{Operation: modal.OpGetAppInfo, Field: "/functionInfoSummaries/*/schedule", Reason: "A function that runs on no schedule has no FunctionInfoSummary.schedule; the sandbox recording's web functions have none."},
		},
		Scenarios: append([]collectortest.Scenario{
			kitClean(),
			kitMemberToken(),
			kitEmptyWorkspace(),
			kitUnassignedServiceUser(),
			kitSSOSignIn(),
			kitNoProxyTokens(),
			kitNoServiceUsers(),
			kitServiceUsersRefused(),
			kitContributorMember(),
			kitEnvironmentRolesRefused(),
			kitTokenWithoutCreationTime(),
			kitAccessOnly(),
			kitDetailsOnly(),
			kitTrust(),
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses:     []collectortest.Response{grpcError(modal.OpTokenInfo, 16, "Token not found")},
			},
		}, kitRecordings(t, "modal")...),
		// The sign-in is the only call whose failure may fail the run.
		Required: []string{modal.OpTokenInfo},
		Operations: []string{
			modal.OpTokenInfo,
			modal.OpListMembers,
			modal.OpListEnvironments,
			modal.OpGetEnvironmentRoles,
			modal.OpListServiceUsers,
			modal.OpListProxyTokens,
			modal.OpListProxyTokenEnvironments,
			modal.OpListSecrets,
			modal.OpListApps,
			modal.OpGetAppInfo,
		},
		// Every gap a fault leaves names the faulted call, since the client
		// builds its errors with componentsdk.ResponseError.
		GapOperations: true,
		Codec:         grpcCodec{},
	})
}

// kitClean is a Team workspace whose token belongs to a Manager, so every
// call succeeds.
func kitClean() collectortest.Scenario {
	result := kitStepPins(kitSteps)
	kitGapPins(result, kitAccessGaps(true, true))
	result["/signed_in_as/provider"] = "modal"
	result["/signed_in_as/kind"] = "user"
	result["/signed_in_as/tenant_id"] = kitWorkspaceID
	result["/signed_in_as/auth_method"] = "api_token"
	return collectortest.Scenario{
		Name:      "clean",
		Responses: kitWorkspace(),
		Expect: map[string]map[string]any{
			accessPath: kitCleanAccess(),
			artifactPath: {
				"/workspace":                                       map[string]any{"id": kitWorkspaceID, "name": kitWorkspaceName},
				"/members/total_count":                             3,
				"/members/owner_count":                             1,
				"/members/manager_count":                           1,
				"/members/member_count":                            1,
				"/members/sign_in":                                 map[string]any{"github_count": 1, "google_count": 2, "saml_count": 0, "other_count": 0},
				"/members/inactive_count":                          2,
				"/members/inventory/0/email":                       "manager@example.com",
				"/members/inventory/0/inactive":                    true,
				"/members/inventory/1/email":                       "member@example.com",
				"/members/inventory/1/last_active_at":              nil,
				"/members/inventory/2/role":                        "owner",
				"/members/inventory/2/sign_in":                     "github",
				"/environments/total_count":                        3,
				"/environments/restricted_count":                   1,
				"/environments/inventory/0":                        map[string]any{"name": "dev", "default": false, "restricted": false, "created_at": "2026-10-02T12:00:00Z", "default_member_role": nil, "blocks_unauthenticated": false, "roles": nil},
				"/environments/inventory/1/default":                true,
				"/environments/inventory/1/blocks_unauthenticated": nil,
				"/environments/inventory/2/default_member_role":    "no_access",
				"/environments/inventory/2/roles": []any{
					map[string]any{"principal": "member@example.com", "kind": "member", "role": "viewer"},
					map[string]any{"principal": "ci-deployer", "kind": "service_user", "role": "contributor"},
				},
				"/service_users/total_count":                  2,
				"/service_users/never_used_count":             1,
				"/service_users/inventory/0/name":             "ci-deployer",
				"/service_users/inventory/1/never_used":       true,
				"/proxy_auth_tokens/total_count":              2,
				"/proxy_auth_tokens/unscoped_count":           1,
				"/proxy_auth_tokens/inventory/0/name":         "prod-caller",
				"/proxy_auth_tokens/inventory/0/environments": []any{"prod"},
				"/proxy_auth_tokens/inventory/1/environments": nil,
				"/secrets/total_count":                        3,
				"/secrets/never_used_count":                   2,
				"/secrets/inventory/0/name":                   "api-key",
				"/secrets/inventory/1/name":                   "db-credentials",
				"/secrets/inventory/1/keys":                   []any{"DB_PASSWORD", "DB_USER"},
				"/secrets/inventory/1/never_used":             false,
				"/apps/deployed_count":                        3,
				"/apps/web_endpoint_count":                    2,
				"/apps/unauthenticated_endpoint_count":        1,
				"/apps/scheduled_function_count":              1,
				"/apps/inventory/0/name":                      "sandbox-public-api",
				"/apps/inventory/0/unauthenticated_endpoints": 1,
				"/apps/inventory/1":                           map[string]any{"name": "old-job", "environment": "prod", "state": "stopped", "created_at": "2026-10-19T12:00:00Z", "web_endpoints": nil, "unauthenticated_endpoints": nil, "scheduled_functions": nil},
				"/apps/inventory/3/name":                      "sandbox-private-api",
				"/apps/inventory/3/unauthenticated_endpoints": 0,
			},
			kitResultPath: result,
		},
	}
}

// kitCleanAccess is the clean workspace's access-posture artifact. The
// owner signs in with GitHub and the others with Google, so no one uses
// SSO. The member was never active and the manager not for 100 days. Of
// the four credentials, sandbox-caller was created 120 days ago. The
// workspace has service users, so the unrestricted credentials and those
// with write access are left out.
func kitCleanAccess() map[string]any {
	return map[string]any{
		"/schema_version": SchemaVersion,
		"/provider":       "modal",
		"/system_type":    "platform",
		"/sign_in":        map[string]any{"sso_configured": false},
		"/members": map[string]any{
			"members_present": true, "member_count": 3,
			"sso_member_count": 0, "sso_coverage_pct": 0,
			"local_members_present": true, "local_member_count": 3,
			"inactive_member_count": 2, "inactive_pct": 67,
		},
		"/admins": map[string]any{
			"admins_present": true, "admin_count": 2, "admin_share_pct": 67,
			"local_admins_present": true, "local_admin_count": 2,
		},
		"/credentials": map[string]any{
			"credentials_present": true, "credential_count": 4,
			"rotation_overdue_credential_count": 1, "rotation_overdue_pct": 25,
		},
		"/root":           collectortest.Absent,
		"/connected_apps": collectortest.Absent,
	}
}

// kitMemberToken is the clean workspace read with a Member's token. Only
// the Owner and Managers can list members and service users, so both lists
// are refused. Their gaps name the Manager role. The access-posture
// artifact leaves out its sign-in, members, and admins, which come from the
// members list. Its credential counts and percentages are left out too,
// since they need the service users.
func kitMemberToken() collectortest.Scenario {
	refused := "User kit-member does not have manage access to workspace kit-workspace. Contact your workspace administrator to update permissions."
	result := kitStepPins(kitSteps)
	refusedGaps := append(kitAccessGaps(false, false),
		kitGap{artifactPath, "/members", componentsdk.CodePermissionDenied},
		kitGap{accessPath, "/sign_in/sso_configured", componentsdk.CodePermissionDenied},
		kitGap{accessPath, "/members", componentsdk.CodePermissionDenied},
		kitGap{accessPath, "/admins", componentsdk.CodePermissionDenied},
		kitGap{artifactPath, "/service_users", componentsdk.CodePermissionDenied},
	)
	for _, v := range credentialValues {
		refusedGaps = append(refusedGaps, kitGap{accessPath, v.pointer, componentsdk.CodePermissionDenied})
	}
	gaps := kitGapPins(result, refusedGaps)
	detailed := fmt.Sprintf("/gaps/%d/", kitGapIndex(gaps, artifactPath, "/members"))
	for field, value := range map[string]any{
		"status": "not_collected", "owner": "customer", "vendor_code": "PERMISSION_DENIED",
		"operation": modal.OpListMembers, "call": 2,
		"missing_permission": modal.RoleManager,
		"warning":            membersRefusedWarning,
	} {
		result[detailed+field] = value
	}
	access := fmt.Sprintf("/gaps/%d/", kitGapIndex(gaps, accessPath, "/members"))
	result[access+"operation"] = modal.OpListMembers
	result[access+"missing_permission"] = modal.RoleManager
	pointers := []kitGap{{path: artifactPath, pointer: "/service_users"}}
	for _, v := range credentialValues {
		pointers = append(pointers, kitGap{path: accessPath, pointer: v.pointer})
	}
	for _, g := range pointers {
		at := fmt.Sprintf("/gaps/%d/", kitGapIndex(gaps, g.path, g.pointer))
		result[at+"operation"] = modal.OpListServiceUsers
		result[at+"missing_permission"] = modal.RoleManager
	}
	return collectortest.Scenario{
		Name: "member token",
		Responses: withResponses(kitWorkspace(),
			grpcError(modal.OpListMembers, 7, refused),
			grpcError(modal.OpListServiceUsers, 7, refused),
		),
		Expect: map[string]map[string]any{
			artifactPath: {"/members": collectortest.Absent, "/service_users": collectortest.Absent, "/environments/total_count": 3, "/apps/deployed_count": 3},
			accessPath: {
				"/sign_in": collectortest.Absent, "/members": collectortest.Absent, "/admins": collectortest.Absent,
				"/credentials": map[string]any{"credentials_present": true},
			},
			kitResultPath: result,
		},
	}
}

// kitTrust is the clean workspace at the trust level. The workspace's ID
// and the signed-in user's are left out, and the workspace's name stays.
func kitTrust() collectortest.Scenario {
	return collectortest.Scenario{
		Name:      "trust",
		Config:    map[string]any{"level": "trust"},
		Responses: kitWorkspace(),
		Expect: map[string]map[string]any{
			artifactPath: {
				"/workspace":           map[string]any{"name": kitWorkspaceName},
				"/members/total_count": 3,
			},
			kitResultPath: {
				"/signed_in_as/provider":  "modal",
				"/signed_in_as/tenant_id": collectortest.Absent,
				"/signed_in_as/id":        collectortest.Absent,
			},
		},
	}
}

// kitEmptyWorkspace is a workspace with its owner, the default environment,
// and nothing else. With no credentials, the credential percentages are
// null.
func kitEmptyWorkspace() collectortest.Scenario {
	main := pb.EnvironmentListItem_builder{Name: "main", EnvironmentId: "en-kitmain0123456789abcd", Default: true, CreatedAt: epoch(kitNow.AddDate(0, 0, -1))}.Build()
	owner := kitMembers().GetMembers()[0]
	result := map[string]any{}
	kitGapPins(result, kitAccessGaps(false, false))
	return collectortest.Scenario{
		Name: "empty workspace",
		Responses: []collectortest.Response{
			grpcOK(modal.OpTokenInfo, kitTokenInfo()),
			grpcOK(modal.OpListMembers, pb.WorkspaceMembersListResponse_builder{Members: []*pb.WorkspaceMembersListItem{owner}}.Build()),
			grpcOK(modal.OpListEnvironments, pb.EnvironmentListResponse_builder{Items: []*pb.EnvironmentListItem{main}}.Build()),
			grpcOK(modal.OpListServiceUsers, kitServiceUsersIn()),
			grpcOK(modal.OpListProxyTokens, pb.WebhookTokenListResponse_builder{}.Build()),
			grpcOK(modal.OpListSecrets, kitSecretsIn()),
			grpcOK(modal.OpListApps, kitAppsIn()),
		},
		Expect: map[string]map[string]any{
			artifactPath: {
				"/members/total_count":           1,
				"/members/inactive_count":        0,
				"/environments/restricted_count": 0,
				"/service_users":                 map[string]any{"total_count": 0, "never_used_count": 0, "inventory": []any{}},
				"/proxy_auth_tokens":             map[string]any{"total_count": 0, "unscoped_count": 0, "inventory": []any{}},
				"/secrets":                       map[string]any{"total_count": 0, "never_used_count": 0, "inventory": []any{}},
				"/apps":                          map[string]any{"deployed_count": 0, "web_endpoint_count": 0, "unauthenticated_endpoint_count": 0, "scheduled_function_count": 0, "inventory": []any{}},
			},
			accessPath: {
				"/members/members_present": true, "/members/member_count": 1, "/members/inactive_pct": 0,
				"/admins/admin_share_pct": 100,
				"/credentials": map[string]any{
					"credentials_present": false, "credential_count": 0,
					"unused_credential_count": 0, "unused_pct": nil,
					"unrestricted_credential_count": 0, "unrestricted_pct": nil,
					"write_access_credential_count": 0, "write_access_pct": nil,
					"rotation_overdue_credential_count": 0, "rotation_overdue_pct": nil,
				},
			},
			kitResultPath: result,
		},
	}
}

// kitUnassignedServiceUser is the clean workspace with unused-bot also in
// the prod roles. Nobody gave unused-bot a role in prod, so it is listed
// with No Access and no role assignment. It is left out of the roles.
func kitUnassignedServiceUser() collectortest.Scenario {
	roles := kitProdRoles()
	roles.SetPrincipalRoles(append(roles.GetPrincipalRoles(), pb.EnvironmentGetRolesResponse_Principal_builder{
		ServiceUserId: "su-kitunused", ServiceUserName: "unused-bot", Role: pb.EnvironmentRole_ENVIRONMENT_ROLE_NO_ACCESS, HasRoleAssignment: proto.Bool(false),
	}.Build()))
	result := map[string]any{}
	kitGapPins(result, kitAccessGaps(true, true))
	return collectortest.Scenario{
		Name:      "unassigned service user",
		Responses: withResponses(kitWorkspace(), grpcOK(modal.OpGetEnvironmentRoles, roles)),
		Expect: map[string]map[string]any{
			artifactPath: {
				"/environments/inventory/2/roles": []any{
					map[string]any{"principal": "member@example.com", "kind": "member", "role": "viewer"},
					map[string]any{"principal": "ci-deployer", "kind": "service_user", "role": "contributor"},
				},
			},
			kitResultPath: result,
		},
	}
}

// kitSSOSignIn is the clean workspace with every member signing in through
// SAML SSO. Every member and admin then counts as an SSO member.
func kitSSOSignIn() collectortest.Scenario {
	members := kitMembers()
	for _, m := range members.GetMembers() {
		m.SetIdentityProviderType(pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_SAML)
	}
	result := map[string]any{}
	kitGapPins(result, kitAccessGaps(true, true))
	return collectortest.Scenario{
		Name:      "SSO sign-in",
		Responses: withResponses(kitWorkspace(), grpcOK(modal.OpListMembers, members)),
		Expect: map[string]map[string]any{
			artifactPath: {"/members/sign_in": map[string]any{"github_count": 0, "google_count": 0, "saml_count": 3, "other_count": 0}},
			accessPath: {
				"/sign_in": map[string]any{"sso_configured": true},
				"/members": map[string]any{
					"members_present": true, "member_count": 3,
					"sso_member_count": 3, "sso_coverage_pct": 100,
					"local_members_present": false, "local_member_count": 0,
					"inactive_member_count": 2, "inactive_pct": 67,
				},
				"/admins/local_admins_present": false,
				"/admins/local_admin_count":    0,
			},
			kitResultPath: result,
		},
	}
}

// kitNoProxyTokens is the clean workspace with no proxy auth tokens and a
// third service user, old-bot, created 200 days ago and last used 100 days
// ago. With no proxy auth tokens, the unused credentials are counted. They
// are unused-bot, never used, and old-bot. The unrestricted credentials and
// those with write access are left out, as in any workspace with service
// users.
func kitNoProxyTokens() collectortest.Scenario {
	users := kitServiceUsers()
	users.SetServiceUsers(append(users.GetServiceUsers(), pb.ServiceUser_builder{
		Name: "old-bot", ServiceUserId: "su-kitold", CreatedBy: "kit-owner",
		CreatedAt: epoch(kitNow.AddDate(0, 0, -200)), LastUsedAt: epoch(kitNow.AddDate(0, 0, -100)),
	}.Build()))
	responses := withResponses(kitWorkspace(),
		grpcOK(modal.OpListServiceUsers, users),
		grpcOK(modal.OpListProxyTokens, pb.WebhookTokenListResponse_builder{}.Build()),
	)
	responses = slices.DeleteFunc(responses, func(r collectortest.Response) bool { return r.Operation == modal.OpListProxyTokenEnvironments })
	result := map[string]any{}
	kitGapPins(result, kitAccessGaps(false, true))
	return collectortest.Scenario{
		Name:      "no proxy auth tokens",
		Responses: responses,
		Expect: map[string]map[string]any{
			artifactPath: {"/service_users/never_used_count": 1, "/proxy_auth_tokens/total_count": 0},
			accessPath: {
				"/credentials": map[string]any{
					"credentials_present": true, "credential_count": 3,
					"unused_credential_count": 2, "unused_pct": 67,
					"rotation_overdue_credential_count": 1, "rotation_overdue_pct": 34,
				},
			},
			kitResultPath: result,
		},
	}
}

// kitNoServiceUsers is the clean workspace with no service users, as on
// Modal's Starter plan. The prod roles list only members. sandbox-caller
// works in every environment, so it is unrestricted, and prod-caller is
// limited to prod. Neither proxy auth token has write access.
func kitNoServiceUsers() collectortest.Scenario {
	roles := kitProdRoles()
	roles.SetPrincipalRoles(slices.DeleteFunc(roles.GetPrincipalRoles(), func(p *pb.EnvironmentGetRolesResponse_Principal) bool { return p.GetServiceUserId() != "" }))
	result := map[string]any{}
	kitGapPins(result, kitAccessGaps(true, false))
	return collectortest.Scenario{
		Name: "no service users",
		Responses: withResponses(kitWorkspace(),
			grpcOK(modal.OpListServiceUsers, kitServiceUsersIn()),
			grpcOK(modal.OpGetEnvironmentRoles, roles),
		),
		Expect: map[string]map[string]any{
			artifactPath: {"/service_users/total_count": 0, "/proxy_auth_tokens/unscoped_count": 1},
			accessPath: {
				"/credentials": map[string]any{
					"credentials_present": true, "credential_count": 2,
					"unrestricted_credential_count": 1, "unrestricted_pct": 50,
					"write_access_credential_count": 0, "write_access_pct": 0,
					"rotation_overdue_credential_count": 1, "rotation_overdue_pct": 50,
				},
			},
			kitResultPath: result,
		},
	}
}

// kitServiceUsersRefused is the clean workspace with the service users
// list refused. With two proxy auth tokens listed, credentials_present is
// still true, and the credential counts and percentages are left out.
func kitServiceUsersRefused() collectortest.Scenario {
	gaps := append(kitAccessGaps(false, false), kitGap{artifactPath, "/service_users", componentsdk.CodePermissionDenied})
	for _, v := range credentialValues {
		gaps = append(gaps, kitGap{accessPath, v.pointer, componentsdk.CodePermissionDenied})
	}
	result := map[string]any{}
	kitGapPins(result, gaps)
	return collectortest.Scenario{
		Name:      "service users refused",
		Responses: withResponses(kitWorkspace(), grpcError(modal.OpListServiceUsers, 7, "Permission denied")),
		Expect: map[string]map[string]any{
			artifactPath:  {"/service_users": collectortest.Absent, "/proxy_auth_tokens/total_count": 2},
			accessPath:    {"/credentials": map[string]any{"credentials_present": true}},
			kitResultPath: result,
		},
	}
}

// kitContributorMember is the clean workspace with the Member a
// Contributor in the restricted environment. No environment then limits
// them, so they count as an admin beside the Owner and the Manager.
func kitContributorMember() collectortest.Scenario {
	roles := kitProdRoles()
	roles.GetPrincipalRoles()[0].SetRole(pb.EnvironmentRole_ENVIRONMENT_ROLE_CONTRIBUTOR)
	result := map[string]any{}
	kitGapPins(result, kitAccessGaps(true, true))
	return collectortest.Scenario{
		Name:      "Member no environment limits",
		Responses: withResponses(kitWorkspace(), grpcOK(modal.OpGetEnvironmentRoles, roles)),
		Expect: map[string]map[string]any{
			accessPath: {"/admins": map[string]any{
				"admins_present": true, "admin_count": 3, "admin_share_pct": 100,
				"local_admins_present": true, "local_admin_count": 3,
			}},
			kitResultPath: result,
		},
	}
}

// kitEnvironmentRolesRefused is the clean workspace with the restricted
// environment's roles refused. Whether it limits the Member is then
// unknown, so the admin values that count them are left out with a partial
// gap. The Owner and the Manager still make the present flags true.
func kitEnvironmentRolesRefused() collectortest.Scenario {
	unknown := []string{"/admins/admin_count", "/admins/admin_share_pct", "/admins/local_admin_count"}
	gaps := append(kitAccessGaps(true, true), kitGap{artifactPath, "/environments/inventory/2/roles", componentsdk.CodePermissionDenied})
	for _, pointer := range unknown {
		gaps = append(gaps, kitGap{accessPath, pointer, componentsdk.CodePermissionDenied})
	}
	result := map[string]any{}
	sorted := kitGapPins(result, gaps)
	for _, pointer := range unknown {
		at := fmt.Sprintf("/gaps/%d/", kitGapIndex(sorted, accessPath, pointer))
		result[at+"status"] = "partial"
		result[at+"unmeasured"] = 1
	}
	return collectortest.Scenario{
		Name:      "environment roles refused",
		Responses: withResponses(kitWorkspace(), grpcError(modal.OpGetEnvironmentRoles, 7, "Permission denied")),
		Expect: map[string]map[string]any{
			accessPath:    {"/admins": map[string]any{"admins_present": true, "local_admins_present": true}},
			kitResultPath: result,
		},
	}
}

// kitTokenWithoutCreationTime is the clean workspace with sandbox-caller
// listed without a creation time, which Modal reports for every proxy auth
// token. The list is not an answer, so the proxy auth tokens and the
// credential counts and percentages are left out with an invalid_response
// gap that names the call. The service users still make
// credentials_present true.
func kitTokenWithoutCreationTime() collectortest.Scenario {
	tokens := kitProxyTokens()
	for _, t := range tokens.GetTokens() {
		if t.GetName() == "sandbox-caller" {
			t.SetCreatedAt(0)
		}
	}
	gaps := append(kitAccessGaps(false, false), kitGap{artifactPath, "/proxy_auth_tokens", componentsdk.CodeInvalidResponse})
	for _, v := range credentialValues {
		gaps = append(gaps, kitGap{accessPath, v.pointer, componentsdk.CodeInvalidResponse})
	}
	result := map[string]any{}
	sorted := kitGapPins(result, gaps)
	result[fmt.Sprintf("/gaps/%d/operation", kitGapIndex(sorted, artifactPath, "/proxy_auth_tokens"))] = modal.OpListProxyTokens
	responses := withResponses(kitWorkspace(), grpcOK(modal.OpListProxyTokens, tokens))
	responses = slices.DeleteFunc(responses, func(r collectortest.Response) bool { return r.Operation == modal.OpListProxyTokenEnvironments })
	return collectortest.Scenario{
		Name:      "proxy auth token without a creation time",
		Responses: responses,
		Expect: map[string]map[string]any{
			artifactPath:  {"/proxy_auth_tokens": collectortest.Absent, "/service_users/total_count": 2},
			accessPath:    {"/credentials": map[string]any{"credentials_present": true}},
			kitResultPath: result,
		},
	}
}

// kitAccessOnly is the clean workspace with collect set to access-posture.
// The detailed artifact is left out, and so are the calls only it needs.
func kitAccessOnly() collectortest.Scenario {
	result := kitStepPins(kitAccessSteps)
	kitGapPins(result, append(kitAccessGaps(true, true), kitGap{artifactPath, "", componentsdk.CodeNotShared}))
	result["/collect/listed"] = []any{"access-posture"}
	result["/collect/left_out"] = []any{"details"}
	return collectortest.Scenario{
		Name:      "access posture only",
		Config:    map[string]any{"collect": []any{"access-posture"}},
		Responses: kitWorkspace(),
		Expect:    map[string]map[string]any{accessPath: kitCleanAccess(), kitResultPath: result},
	}
}

// kitDetailsOnly is the clean workspace with collect set to details. The
// access-posture artifact is left out, with none of its gaps. Its
// not_shared gap has the artifact's schema ID and no path.
func kitDetailsOnly() collectortest.Scenario {
	result := kitStepPins(kitSteps)
	result["/gaps/0/schema"] = accessSchema
	result["/gaps/0/path"] = collectortest.Absent
	result["/gaps/0/code"] = string(componentsdk.CodeNotShared)
	result["/gaps/1"] = collectortest.Absent
	result["/collect/listed"] = []any{"details"}
	result["/collect/left_out"] = []any{"access-posture"}
	return collectortest.Scenario{
		Name:      "details only",
		Config:    map[string]any{"collect": []any{"details"}},
		Responses: kitWorkspace(),
		Expect:    map[string]map[string]any{artifactPath: {"/members/total_count": 3, "/apps/deployed_count": 3}, kitResultPath: result},
	}
}

// kitGap is a gap a scenario's collector result holds.
type kitGap struct {
	path, pointer string
	code          componentsdk.Code
}

// kitAccessGaps is the gaps every internal-level run's access-posture
// artifact has: an unsupported gap on each value Modal does not report. A
// workspace with proxy auth tokens also has one on the unused credentials.
// A workspace with service users has a not_read gap on the unrestricted
// credentials and those with write access.
func kitAccessGaps(proxyTokens, serviceUsers bool) []kitGap {
	pointers := []string{
		"/sign_in/sso_required", "/sign_in/mfa_required", "/sign_in/scim_enabled",
		"/members/external_members_present", "/members/external_member_count",
		"/members/local_mfa_member_count", "/members/local_mfa_coverage_pct",
		"/admins/local_mfa_admin_count", "/admins/local_admin_mfa_coverage_pct",
		"/root", "/connected_apps",
		"/credentials/never_expiring_credential_count", "/credentials/never_expiring_pct",
	}
	if proxyTokens {
		pointers = append(pointers, "/credentials/unused_credential_count", "/credentials/unused_pct")
	}
	gaps := make([]kitGap, 0, len(pointers)+4)
	for _, p := range pointers {
		gaps = append(gaps, kitGap{accessPath, p, componentsdk.CodeUnsupported})
	}
	if serviceUsers {
		for _, p := range []string{
			"/credentials/unrestricted_credential_count", "/credentials/unrestricted_pct",
			"/credentials/write_access_credential_count", "/credentials/write_access_pct",
		} {
			gaps = append(gaps, kitGap{accessPath, p, componentsdk.CodeNotRead})
		}
	}
	return gaps
}

// kitGapPins adds to pins each gap's path, pointer, and code, in the order
// the collector result sorts gaps, and that there are no more. It returns
// the gaps in that order.
func kitGapPins(pins map[string]any, gaps []kitGap) []kitGap {
	sorted := slices.Clone(gaps)
	slices.SortFunc(sorted, func(a, b kitGap) int { return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.pointer, b.pointer)) })
	for i, g := range sorted {
		pins[fmt.Sprintf("/gaps/%d/path", i)] = g.path
		pins[fmt.Sprintf("/gaps/%d/pointer", i)] = g.pointer
		pins[fmt.Sprintf("/gaps/%d/code", i)] = string(g.code)
	}
	pins[fmt.Sprintf("/gaps/%d", len(sorted))] = collectortest.Absent
	return sorted
}

// kitGapIndex is the index of the gap at path and pointer in gaps.
func kitGapIndex(gaps []kitGap, path, pointer string) int {
	return slices.IndexFunc(gaps, func(g kitGap) bool { return g.path == path && g.pointer == pointer })
}

func kitServiceUsersIn(users ...*pb.ServiceUser) *pb.ServiceUserListResponse {
	return pb.ServiceUserListResponse_builder{ServiceUsers: users}.Build()
}

// kitRecordings loads the scenarios TestRecord in record_test.go records
// from sandboxes, and logs each one not recorded yet.
func kitRecordings(t *testing.T, names ...string) []collectortest.Scenario {
	t.Helper()
	var out []collectortest.Scenario
	for _, name := range names {
		path := filepath.Join("testdata", "recordings", name+".json")
		sc, err := collectortest.LoadScenario(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			t.Logf("no recording at %s yet", path)
		case err != nil:
			t.Fatal(err)
		default:
			out = append(out, sc)
		}
	}
	return out
}

// kitStepPins pins a run's steps, in order, and that there are no more.
func kitStepPins(steps []string) map[string]any {
	pins := map[string]any{}
	for i, name := range steps {
		pins[fmt.Sprintf("/steps/%d/name", i)] = name
	}
	pins[fmt.Sprintf("/steps/%d", len(steps))] = collectortest.Absent
	return pins
}

// A trust run writes none of the workspace's IDs, or its members',
// environments', service users', tokens', or apps', in any artifact. An
// audit run still writes the workspace's ID.
func TestATrustRunWritesNoIDs(t *testing.T) {
	ids := []string{kitWorkspaceID, kitManagerUserID, kitProdEnvID, "en-kitdev0123456789abcde", "us-kit-member", "mb-kit-owner", "su-kitdeployer", "wk-kitcaller", "ap-kitpublic"}
	for _, a := range runAtLevel(t, componentsdk.LevelTrust).Artifacts {
		for _, id := range ids {
			if strings.Contains(string(a.Data), id) {
				t.Errorf("the trust run wrote %s in %s", id, a.Path)
			}
		}
	}
	for _, a := range runAtLevel(t, componentsdk.LevelAudit).Artifacts {
		if a.Path != artifactPath {
			continue
		}
		var out Output
		if err := json.Unmarshal(a.Data, &out); err != nil {
			t.Fatal(err)
		}
		if out.Workspace.ID != kitWorkspaceID {
			t.Errorf("the audit run wrote workspace ID %q, want %q", out.Workspace.ID, kitWorkspaceID)
		}
		return
	}
	t.Fatalf("the audit run wrote no %s", artifactPath)
}

// The run declares the workspace its token belongs to and the environments
// the token can see. An environment whose roles could not be read leaves the
// environments incomplete, and a run that could not list them declares them
// with none counted. Below the audit level the inventory, and so the
// environments themselves, are left out, and only the count of them is kept.
func TestRunDeclaresTheWorkspaceAndEnvironments(t *testing.T) {
	zero, one, three, complete, incomplete := 0, 1, 3, true, false
	workspace := func(count *int) componentsdk.ResultTarget {
		return componentsdk.ResultTarget{
			Kind: componentsdk.TargetWorkspace, ChosenBy: componentsdk.ChosenByDiscovery,
			At: &componentsdk.Location{Path: artifactPath, Pointer: "/workspace"}, Name: []string{"/name"},
			Count: count, Complete: &complete,
		}
	}
	environments := componentsdk.ResultTarget{
		Kind: componentsdk.TargetEnvironment, ChosenBy: componentsdk.ChosenByDiscovery,
		At: &componentsdk.Location{Path: artifactPath, Pointer: "/environments/inventory"}, Name: []string{"/name"},
		Assessed: &componentsdk.Location{Path: artifactPath, Pointer: "/environments/total_count"},
		Count:    &three, Complete: &complete,
	}
	rolesRefused := environments
	rolesRefused.Complete = &incomplete
	listRefused := rolesRefused
	listRefused.Assessed, listRefused.Count = nil, &zero
	trustEnvironments := componentsdk.ResultTarget{
		Kind: componentsdk.TargetEnvironment, ChosenBy: componentsdk.ChosenByDiscovery,
		Assessed: &componentsdk.Location{Path: artifactPath, Pointer: "/environments/total_count"},
	}
	cases := []struct {
		name string
		res  componentsdk.InProcessResult
		want []componentsdk.ResultTarget
	}{
		{"audit", runAtLevel(t, componentsdk.LevelAudit), []componentsdk.ResultTarget{workspace(&one), environments}},
		{"trust", runAtLevel(t, componentsdk.LevelTrust), []componentsdk.ResultTarget{workspace(nil), trustEnvironments}},
		{
			"audit, roles refused",
			runAtLevel(t, componentsdk.LevelAudit, grpcError(modal.OpGetEnvironmentRoles, 7, "permission denied")),
			[]componentsdk.ResultTarget{workspace(&one), rolesRefused},
		},
		{
			"audit, environments refused",
			runAtLevel(t, componentsdk.LevelAudit, grpcError(modal.OpListEnvironments, 7, "permission denied")),
			[]componentsdk.ResultTarget{workspace(&one), listRefused},
		},
	}
	for _, tc := range cases {
		if !reflect.DeepEqual(tc.res.Result.Targets, tc.want) {
			got, _ := json.Marshal(tc.res.Result.Targets)
			want, _ := json.Marshal(tc.want)
			t.Errorf("%s: targets = %s, want %s", tc.name, got, want)
		}
		for _, f := range tc.res.Result.Checks {
			t.Errorf("%s: check finding %+v", tc.name, f)
		}
	}
}

// runAtLevel runs the clean workspace at level, with first answering
// before the clean answers. A replay outside the kit can't read gRPC
// request bodies, so each canned answer goes to every request of its
// operation.
func runAtLevel(t *testing.T, level componentsdk.Level, first ...collectortest.Response) componentsdk.InProcessResult {
	t.Helper()
	responses := append(first, kitWorkspace()...)
	for i := range responses {
		responses[i].RequestBody = ""
	}
	replay, err := collectortest.NewReplay(collectortest.Scenario{Name: t.Name(), Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    map[string]any{"level": string(level)},
		Secrets:   kitSecrets(),
		Transport: replay,
		Clock:     func() time.Time { return kitNow },
	})
	if res.ExitCode != 0 {
		t.Fatalf("the %s run exited %d: %+v", level, res.ExitCode, res.Failure)
	}
	return res
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	cases := map[string]struct {
		config  map[string]any
		secrets map[string]string
	}{
		"an unknown setting": {map[string]any{"workspace": kitWorkspaceName}, kitSecrets()},
		"no token ID":        {map[string]any{}, map[string]string{tokenSecretEnv: kitTokenSecret}},
		"no token secret":    {map[string]any{}, map[string]string{tokenIDEnv: kitTokenID}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
				Config:  tc.config,
				Secrets: tc.secrets,
			})
			if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
				t.Errorf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
			}
		})
	}
}
