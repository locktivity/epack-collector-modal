package collector

import (
	"maps"
	"slices"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated workspaces are rosters the simulator answers for, each with
// the values roster.Derive computes from it. A value the collector reports
// otherwise is listed with a verdict and a note that says where in the
// collector's code it was checked, so a new difference fails, and so does a
// listed one that goes away.

// simStanding are the differences every workspace shows. The collector
// leaves out what Modal doesn't report, each value with an unsupported gap
// (accessUnsupported in access.go). It counts the proxy auth tokens and
// service users it can list as the credentials, and an unscoped proxy auth
// token as unrestricted (accessCredentials).
var simStanding = simulate.Same(simulate.Gap, "accessUnsupported in access.go: Modal's API doesn't report it, so the collector leaves it out with an unsupported gap.",
	"/sign_in/sso_required", "/sign_in/mfa_required", "/sign_in/scim_enabled",
	"/members/external_members_present", "/members/external_member_count",
	"/members/local_mfa_member_count", "/members/local_mfa_coverage_pct",
	"/admins/local_mfa_admin_count", "/admins/local_admin_mfa_coverage_pct",
	"/root/root_account_count", "/root/root_accounts_present", "/root/root_mfa_account_count", "/root/root_mfa_coverage_pct", "/root/root_access_keys_present",
	"/connected_apps/app_count", "/connected_apps/apps_present",
	"/credentials/never_expiring_credential_count", "/credentials/never_expiring_pct",
	"/credentials/unused_credential_count", "/credentials/unused_pct",
).With(
	simulate.Same(simulate.Definition, "accessCredentials counts the proxy auth tokens and service users Modal lists. Modal lists no member's API tokens, which the schema's machine credentials include and Derive counts.",
		"/credentials/credential_count", "/credentials/write_access_credential_count", "/credentials/write_access_pct"),
	simulate.Same(simulate.Definition, "accessCredentials counts an unscoped proxy auth token as unrestricted. It can only call web endpoints, which the schema makes a narrower scope than full access, and Derive counts members' API tokens instead.",
		"/credentials/unrestricted_credential_count", "/credentials/unrestricted_pct"),
)

var simUncompared = map[string]string{
	"/credentials/rotation_overdue_credential_count": simTokenAge,
	"/credentials/rotation_overdue_pct":              simTokenAge,
}

// simTokenAge says why the rosters give no rotation values.
const simTokenAge = "The sandbox roster leaves out when its proxy auth token and the members' API tokens were made, since they age each day, so Derive gives no rotation values for any scenario built on it."

func simScenarios(t testing.TB) []simulate.Scenario {
	return []simulate.Scenario{{Name: "sandbox", Roster: simBase(t)}}
}

func TestSimulatedWorkspaces(t *testing.T) {
	simHarness(simStanding).Tenants(t, simScenarios(t))
}

// simContractKnown lists, by ShapeDifference.Key, the ways the simulator's
// answers are known to differ from the recording's, with why.
var simContractKnown = map[string]string{
	"modal.apps.info.get functionInfoSummaries.fu-nightly_job: unrecorded field": simFunctionIDs,
	"modal.apps.info.get functionInfoSummaries.fu-private_api: unrecorded field": simFunctionIDs,
	"modal.apps.info.get functionInfoSummaries.fu-public_api: unrecorded field":  simFunctionIDs,
}

// simFunctionIDs says why the function summaries differ.
const simFunctionIDs = "Modal keys an app's function summaries by function ID, and the simulator's IDs are its own."

// TestSimulatorMatchesRecording compares the shape of each answer the
// simulator gives for the sandbox roster with the recording's answers to the
// same call, read as JSON through grpcCodec, so the simulator cannot drift
// from Modal's API unseen: a field it gives that Modal doesn't, of another
// type, or one every recorded answer has that it lacks, fails here, in the
// pull request that brings a new recording.
func TestSimulatorMatchesRecording(t *testing.T) {
	rec, err := simulate.LoadRecorded("testdata/recordings/modal.json")
	if err != nil {
		t.Fatal(err)
	}
	var decoded []collectortest.Response
	for _, r := range newModalSim(simBase(t), kitNow) {
		body, err := grpcCodec{}.DecodeResponse(r.Operation, r.Header, []byte(r.Body))
		if err != nil {
			t.Fatalf("%s: %v", r.Operation, err)
		}
		r.Body = string(body)
		decoded = append(decoded, r)
	}
	seen := map[string]bool{}
	for _, d := range rec.Check(decoded) {
		seen[d.Key()] = true
		if why, known := simContractKnown[d.Key()]; known {
			t.Logf("known: %s (%s)", d, why)
			continue
		}
		t.Errorf("%s", d)
	}
	for _, k := range slices.Sorted(maps.Keys(simContractKnown)) {
		if !seen[k] {
			t.Errorf("listed as known, but the simulator now matches the recording: %s", k)
		}
	}
}
