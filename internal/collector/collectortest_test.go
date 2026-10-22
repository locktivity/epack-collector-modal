package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// kitNow is the time the hand-built scenarios run at.
var kitNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/modal.collector-result.json"

// kitSteps are a run's steps in order.
var kitSteps = []string{"sign_in", "members", "environments", "tokens", "workloads"}

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
	result := kitStepPins()
	result["/gaps/0"] = collectortest.Absent
	result["/signed_in_as/provider"] = "modal"
	result["/signed_in_as/kind"] = "user"
	result["/signed_in_as/tenant_id"] = kitWorkspaceID
	result["/signed_in_as/auth_method"] = "api_token"
	return collectortest.Scenario{
		Name:      "clean",
		Responses: kitWorkspace(),
		Expect: map[string]map[string]any{
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

// kitMemberToken is the clean workspace read with a Member's token. Only
// the Owner and Managers can list members, so the members are left out with
// a permission_denied gap naming the Manager role.
func kitMemberToken() collectortest.Scenario {
	result := kitStepPins()
	for field, value := range map[string]any{
		"pointer": "/members", "status": "not_collected",
		"code": "permission_denied", "owner": "customer", "vendor_code": "PERMISSION_DENIED",
		"operation": modal.OpListMembers, "call": 2,
		"missing_permission": modal.RoleManager,
		"warning":            membersRefusedWarning,
	} {
		result["/gaps/0/"+field] = value
	}
	result["/gaps/1"] = collectortest.Absent
	responses := kitWorkspace()
	responses[1] = grpcError(modal.OpListMembers, 7, "User kit-member does not have manage access to workspace kit-workspace. Contact your workspace administrator to update permissions.")
	return collectortest.Scenario{
		Name:      "member token",
		Responses: responses,
		Expect: map[string]map[string]any{
			artifactPath:  {"/members": collectortest.Absent, "/environments/total_count": 3, "/apps/deployed_count": 3},
			kitResultPath: result,
		},
	}
}

// kitEmptyWorkspace is a workspace with its owner, the default environment,
// and nothing else.
func kitEmptyWorkspace() collectortest.Scenario {
	main := pb.EnvironmentListItem_builder{Name: "main", EnvironmentId: "en-kitmain0123456789abcd", Default: true, CreatedAt: epoch(kitNow.AddDate(0, 0, -1))}.Build()
	owner := kitMembers().GetMembers()[0]
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
			kitResultPath: {"/gaps/0": collectortest.Absent},
		},
	}
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
func kitStepPins() map[string]any {
	pins := map[string]any{}
	for i, name := range kitSteps {
		pins[fmt.Sprintf("/steps/%d/name", i)] = name
	}
	pins[fmt.Sprintf("/steps/%d", len(kitSteps))] = collectortest.Absent
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
