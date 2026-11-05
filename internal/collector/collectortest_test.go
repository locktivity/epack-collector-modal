package collector

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
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

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/modal.collector-result.json"

// kitSteps are a run's steps in order.
var kitSteps = []string{"sign_in", "members", "environments", "tokens", "workloads"}

// kitAccessSteps are the steps of a run that collects only the
// access-posture artifact.
var kitAccessSteps = []string{"sign_in", "members", "tokens"}

// TestCollectorKit runs the collector against the scenarios below and the
// one recorded from the sandbox, then injects faults into each operation's
// calls and checks the output against the schema, every collection level,
// and the credential and sensitivity rules. grpcCodec lets the kit read
// Modal's protobuf bodies as JSON.
func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  map[string]any{"level": "internal"},
		Secrets: kitSecrets(),
		Clock:   kitNow,
		Scenarios: append([]collectortest.Scenario{
			kitClean(),
			kitMemberToken(),
			kitEmptyWorkspace(),
			kitUnassignedServiceUser(),
			kitSSOSignIn(),
			kitNoProxyTokens(),
			kitNoServiceUsers(),
			kitServiceUsersRefused(),
			kitTokenWithoutCreationTime(),
			kitAccessOnly(),
			kitDetailsOnly(),
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

// kitTokenWithoutCreationTime is the clean workspace with sandbox-caller
// listed without a creation time. Its age is unknown, so the credentials
// overdue for rotation are left out with a partial gap.
func kitTokenWithoutCreationTime() collectortest.Scenario {
	tokens := kitProxyTokens()
	for _, t := range tokens.GetTokens() {
		if t.GetName() == "sandbox-caller" {
			t.SetCreatedAt(0)
		}
	}
	rotation := []string{"/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct"}
	gaps := kitAccessGaps(true, true)
	for _, pointer := range rotation {
		gaps = append(gaps, kitGap{accessPath, pointer, componentsdk.CodeInvalidResponse})
	}
	result := map[string]any{}
	sorted := kitGapPins(result, gaps)
	for _, pointer := range rotation {
		at := fmt.Sprintf("/gaps/%d/", kitGapIndex(sorted, accessPath, pointer))
		result[at+"status"] = "partial"
		result[at+"unmeasured"] = 1
	}
	return collectortest.Scenario{
		Name:      "proxy auth token without a creation time",
		Responses: withResponses(kitWorkspace(), grpcOK(modal.OpListProxyTokens, tokens)),
		Expect: map[string]map[string]any{
			artifactPath: {"/proxy_auth_tokens/inventory/1/name": "sandbox-caller", "/proxy_auth_tokens/inventory/1/created_at": nil},
			accessPath: {
				"/credentials": map[string]any{"credentials_present": true, "credential_count": 4},
			},
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
