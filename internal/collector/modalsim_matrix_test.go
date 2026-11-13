package collector

import (
	"slices"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated matrix varies the sandbox's Member, its proxy auth token,
// a service user and a restricted environment along the axes below. Each
// one-at-a-time row changes one setting, so a difference it shows belongs to
// that setting and is listed in simMatrixAlone. The pairwise rows put every
// two settings together at least once, and a difference none of a row's
// settings shows alone must be listed in simMatrixTogether.

// simMatrixBase is the sandbox with every member's activity settled: the
// owner signed in a day ago and the Member five days ago. No member's MFA
// is known, as Modal never reports it.
func simMatrixBase(t testing.TB) *roster.Roster {
	t.Helper()
	reals, err := simBase(t).Realizations()
	if err != nil {
		t.Fatal(err)
	}
	r := reals[0].Roster
	for i, a := range r.Accounts {
		switch a.Key {
		case "owner":
			r.Accounts[i].SignedInDaysAgo = new(1)
		case "member":
			r.Accounts[i].SignedInDaysAgo = new(5)
		}
	}
	r.Terms.WorkspaceCredentialPermissions["service_user"] = roster.PermissionsFull
	return r
}

func onMember(change func(*roster.Account)) func(*roster.Roster) {
	return simulate.OnAccount("member", change)
}

func onCaller(change func(*roster.MachineCredential)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		i := slices.IndexFunc(r.Workspace.Credentials, func(m roster.MachineCredential) bool { return m.Key == "caller" })
		change(&r.Workspace.Credentials[i])
	}
}

func simMatrixAxes() []roster.Axis {
	return []roster.Axis{
		{Name: "role", Values: []roster.Value{
			{Name: "member"},
			{Name: "manager", Change: onMember(func(a *roster.Account) { a.Roles = []string{"Manager"} })},
			{Name: "owner", Change: onMember(func(a *roster.Account) { a.Roles = []string{"Owner"} })},
		}},
		{Name: "login", Values: []roster.Value{
			{Name: "google"},
			{Name: "github", Change: onMember(func(a *roster.Account) { a.Logins = []string{"github"} })},
			{Name: "saml", Change: func(r *roster.Roster) {
				onMember(func(a *roster.Account) { a.Logins = []string{"saml"} })(r)
				r.Workspace.SingleSignOn = true
			}},
		}},
		{Name: "activity", Values: []roster.Value{
			{Name: "recent"},
			{Name: "100_days_ago", Change: onMember(func(a *roster.Account) { a.SignedInDaysAgo = new(100) })},
			{Name: "never", Change: onMember(func(a *roster.Account) { a.SignedInDaysAgo = nil })},
		}},
		{Name: "proxy_token", Values: []roster.Value{
			{Name: "unscoped"},
			{Name: "scoped", Change: onCaller(func(m *roster.MachineCredential) { simulate.SetExtra(&m.Extra, "environments", []string{"prod"}) })},
			{Name: "none", Change: onCaller(func(m *roster.MachineCredential) { m.Active = false })},
		}},
		{Name: "service_user", Values: []roster.Value{
			{Name: "none"},
			{Name: "used", Change: func(r *roster.Roster) {
				m := roster.MachineCredential{Key: "deployer", Active: true, CreatedDaysAgo: new(10), LastUsedDaysAgo: new(1), Permissions: "service_user"}
				simulate.SetExtra(&m.Extra, "kind", "service_user")
				simulate.SetExtra(&m.Extra, "name", "ci-deployer")
				r.Workspace.Credentials = append(r.Workspace.Credentials, m)
			}},
		}},
		{Name: "environments", Values: []roster.Value{
			{Name: "open"},
			{Name: "prod_restricted", Change: func(r *roster.Roster) {
				var envs map[string]map[string]any
				simulate.Extra(r.Workspace.Extra, "environments", &envs)
				envs["prod"]["restricted"] = true
				simulate.SetExtra(&r.Workspace.Extra, "environments", envs)
			}},
		}},
	}
}

// simMatrixAlone lists, by axis=value, the differences a setting shows on
// its own.
var simMatrixAlone = map[string]simulate.Differences{
	"proxy_token=none": simulate.Same(simulate.Definition,
		"accessCredentials counts the proxy auth tokens and service users Modal lists, so without them the workspace has no credentials and none unused. Derive counts the members' API tokens, which Modal doesn't list.",
		"/credentials/credentials_present", "/credentials/unused_credential_count", "/credentials/unused_pct"),
	"environments=prod_restricted": simulate.Same(simulate.Unmodeled,
		"accessPeople counts a Member as an admin only when no restricted environment limits them, as Modal's RBAC does. The roster's terms give the Member role one class, admin here, so Derive can't express the restriction.",
		"/admins/admin_count", "/admins/admin_share_pct", "/admins/local_admin_count"),
}

func TestSimulatedMatrix(t *testing.T) {
	simHarness(simStanding).Matrix(t, simMatrixBase(t), simMatrixAxes(), simMatrixAlone, nil)
}
