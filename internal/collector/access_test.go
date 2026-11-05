package collector

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
)

const (
	github = pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GITHUB
	google = pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GOOGLE_OAUTH
	saml   = pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_SAML

	owner   = pb.MemberRole_MEMBER_ROLE_OWNER
	manager = pb.MemberRole_MEMBER_ROLE_MANAGER
	user    = pb.MemberRole_MEMBER_ROLE_USER
)

// testMember is a member with role who signs in with provider and was last
// active at active, or never when active is zero.
func testMember(role pb.MemberRole, provider pb.IdentityProviderType, active time.Time) *pb.WorkspaceMembersListItem {
	b := pb.WorkspaceMembersListItem_builder{MemberRole: role, IdentityProviderType: provider}
	if !active.IsZero() {
		b.LastActiveAt = epoch(active)
	}
	return b.Build()
}

func testServiceUser(created, used time.Time) *pb.ServiceUser {
	b := pb.ServiceUser_builder{Name: "bot"}
	if !created.IsZero() {
		b.CreatedAt = epoch(created)
	}
	if !used.IsZero() {
		b.LastUsedAt = epoch(used)
	}
	return b.Build()
}

func testProxyToken(created time.Time, scoped bool) *pb.WebhookToken {
	b := pb.WebhookToken_builder{Name: "caller", Scoped: scoped}
	if !created.IsZero() {
		b.CreatedAt = epoch(created)
	}
	return b.Build()
}

// daysAgo is the time n days before kitNow.
func daysAgo(n int) time.Time {
	return kitNow.AddDate(0, 0, -n)
}

// buildTestAccess builds the access-posture artifact from src at the audit
// level, or below it when audit is false. It returns the artifact as JSON
// and the gaps, each as its pointer and code.
func buildTestAccess(t *testing.T, src accessSources, audit bool) (map[string]any, map[string]componentsdk.Code) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	out := buildAccess(src, kitNow, audit, gapLog{rec: rec})
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	gaps := map[string]componentsdk.Code{}
	for _, g := range rec.Gaps() {
		if g.Path != accessPath {
			t.Errorf("gap %s is on %s, want %s", g.Pointer, g.Path, accessPath)
		}
		gaps[g.Pointer] = g.Code
	}
	return doc, gaps
}

// section returns the object at name in doc, or nil when it is left out.
func section(doc map[string]any, name string) map[string]any {
	m, _ := doc[name].(map[string]any)
	return m
}

// wantSection checks that doc's section name holds exactly want.
func wantSection(t *testing.T, doc map[string]any, name string, want map[string]any) {
	t.Helper()
	got := section(doc, name)
	wantJSON, _ := json.Marshal(want)
	var normalized map[string]any
	_ = json.Unmarshal(wantJSON, &normalized)
	if !reflect.DeepEqual(got, normalized) {
		gotJSON, _ := json.Marshal(got)
		t.Errorf("%s is %s, want %s", name, gotJSON, wantJSON)
	}
}

// wantGap checks that pointer has a gap with code.
func wantGap(t *testing.T, gaps map[string]componentsdk.Code, pointer string, code componentsdk.Code) {
	t.Helper()
	if got, ok := gaps[pointer]; !ok || got != code {
		t.Errorf("gap on %s is %q, want %q", pointer, got, code)
	}
}

// wantNoGap checks that pointer has no gap.
func wantNoGap(t *testing.T, gaps map[string]componentsdk.Code, pointer string) {
	t.Helper()
	if code, ok := gaps[pointer]; ok {
		t.Errorf("gap on %s is %q, want none", pointer, code)
	}
}

// Modal reports neither sso_required nor mfa_required, so both get an
// unsupported gap. sso_configured comes from how members sign in.
func TestAccessSignIn(t *testing.T) {
	cases := map[string]struct {
		members []*pb.WorkspaceMembersListItem
		want    bool
	}{
		"no member uses SAML":  {[]*pb.WorkspaceMembersListItem{testMember(owner, github, daysAgo(1)), testMember(user, google, daysAgo(1))}, false},
		"one member uses SAML": {[]*pb.WorkspaceMembersListItem{testMember(owner, github, daysAgo(1)), testMember(user, saml, daysAgo(1))}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			doc, gaps := buildTestAccess(t, accessSources{members: tc.members}, true)
			wantSection(t, doc, "sign_in", map[string]any{"sso_configured": tc.want})
			for _, pointer := range []string{"/sign_in/sso_required", "/sign_in/mfa_required", "/sign_in/scim_enabled"} {
				wantGap(t, gaps, pointer, componentsdk.CodeUnsupported)
			}
		})
	}
}

// Modal does not report MFA, so local_admin_mfa_coverage_pct has an
// unsupported gap. local_admins_present says whether any Owner or Manager
// signs in without SAML.
func TestAccessAdmins(t *testing.T) {
	cases := map[string]struct {
		members []*pb.WorkspaceMembersListItem
		want    map[string]any
	}{
		"an owner with GitHub and a manager with SAML": {
			[]*pb.WorkspaceMembersListItem{testMember(owner, github, daysAgo(1)), testMember(manager, saml, daysAgo(1)), testMember(user, google, daysAgo(1))},
			map[string]any{"admins_present": true, "admin_count": 2, "admin_share_pct": 67, "local_admins_present": true, "local_admin_count": 1},
		},
		"every admin uses SAML": {
			[]*pb.WorkspaceMembersListItem{testMember(owner, saml, daysAgo(1)), testMember(manager, saml, daysAgo(1)), testMember(user, github, daysAgo(1))},
			map[string]any{"admins_present": true, "admin_count": 2, "admin_share_pct": 67, "local_admins_present": false, "local_admin_count": 0},
		},
		"no admins": {
			[]*pb.WorkspaceMembersListItem{testMember(user, github, daysAgo(1)), testMember(user, google, daysAgo(1)), testMember(user, google, daysAgo(1))},
			map[string]any{"admins_present": false, "admin_count": 0, "admin_share_pct": 0, "local_admins_present": false, "local_admin_count": 0},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			doc, gaps := buildTestAccess(t, accessSources{members: tc.members}, true)
			wantSection(t, doc, "admins", tc.want)
			wantGap(t, gaps, "/admins/local_admin_mfa_coverage_pct", componentsdk.CodeUnsupported)
			wantGap(t, gaps, "/admins/local_mfa_admin_count", componentsdk.CodeUnsupported)
		})
	}
}

// Modal does not report expiry, so never_expiring_pct has an unsupported
// gap whether or not there are credentials.
func TestAccessNeverExpiring(t *testing.T) {
	cases := map[string]struct {
		src     accessSources
		present bool
	}{
		"credentials": {accessSources{serviceUsers: []*pb.ServiceUser{testServiceUser(daysAgo(1), daysAgo(1))}}, true},
		"none":        {accessSources{}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			doc, gaps := buildTestAccess(t, tc.src, true)
			if got := section(doc, "credentials")["credentials_present"]; got != tc.present {
				t.Errorf("credentials_present is %v, want %v", got, tc.present)
			}
			wantGap(t, gaps, "/credentials/never_expiring_pct", componentsdk.CodeUnsupported)
			wantGap(t, gaps, "/credentials/never_expiring_credential_count", componentsdk.CodeUnsupported)
		})
	}
}

// A member last active more than 90 days before the run, or never, is
// inactive. One last active exactly 90 days before is not.
func TestAccessInactiveMembers(t *testing.T) {
	members := []*pb.WorkspaceMembersListItem{
		testMember(owner, github, daysAgo(1)),
		testMember(user, google, daysAgo(90)),
		testMember(user, google, daysAgo(91)),
		testMember(user, google, time.Time{}),
	}
	doc, _ := buildTestAccess(t, accessSources{members: members}, true)
	wantSection(t, doc, "members", map[string]any{
		"members_present": true, "member_count": 4,
		"sso_member_count": 0, "sso_coverage_pct": 0,
		"local_members_present": true, "local_member_count": 4,
		"inactive_member_count": 2, "inactive_pct": 50,
	})

	doc, _ = buildTestAccess(t, accessSources{members: []*pb.WorkspaceMembersListItem{}}, true)
	wantSection(t, doc, "members", map[string]any{
		"members_present": false, "member_count": 0,
		"sso_member_count": 0, "sso_coverage_pct": nil,
		"local_members_present": false, "local_member_count": 0,
		"inactive_member_count": 0, "inactive_pct": nil,
	})
}

// Percentages round as the schema says: SSO coverage down, the inactive
// rate and admin share up.
func TestAccessRounding(t *testing.T) {
	members := []*pb.WorkspaceMembersListItem{
		testMember(owner, saml, daysAgo(1)),
		testMember(user, saml, daysAgo(1)),
		testMember(user, github, time.Time{}),
	}
	doc, _ := buildTestAccess(t, accessSources{members: members}, false)
	m, a := section(doc, "members"), section(doc, "admins")
	if m["sso_coverage_pct"] != 66.0 || m["inactive_pct"] != 34.0 || a["admin_share_pct"] != 34.0 {
		t.Errorf("sso_coverage_pct %v, inactive_pct %v, admin_share_pct %v; want 66, 34, 34", m["sso_coverage_pct"], m["inactive_pct"], a["admin_share_pct"])
	}
}

// A credential created more than 90 days before the run is overdue for
// rotation. One created exactly 90 days before is not. In a workspace with
// service users, the unrestricted credentials and those with write access
// are left out with a not_read gap, since they depend on environment roles.
func TestAccessCredentials(t *testing.T) {
	src := accessSources{
		serviceUsers: []*pb.ServiceUser{
			testServiceUser(daysAgo(91), daysAgo(1)),
			testServiceUser(daysAgo(90), daysAgo(1)),
		},
		proxyTokens: []*pb.WebhookToken{
			testProxyToken(daysAgo(200), false),
			testProxyToken(daysAgo(5), true),
		},
	}
	doc, gaps := buildTestAccess(t, src, true)
	wantSection(t, doc, "credentials", map[string]any{
		"credentials_present": true, "credential_count": 4,
		"rotation_overdue_credential_count": 2, "rotation_overdue_pct": 50,
	})
	wantGap(t, gaps, "/credentials/unused_pct", componentsdk.CodeUnsupported)
	wantGap(t, gaps, "/credentials/unused_credential_count", componentsdk.CodeUnsupported)
	for _, v := range roleValues {
		wantGap(t, gaps, v.pointer, componentsdk.CodeNotRead)
	}
}

// When a service user or proxy auth token has no creation time, its age is
// unknown. The credentials overdue for rotation are then left out with a
// partial gap that counts the credentials without one. Below the audit
// level, only the percentage has a gap.
func TestAccessCredentialsWithoutCreationTime(t *testing.T) {
	src := accessSources{
		serviceUsers: []*pb.ServiceUser{
			testServiceUser(daysAgo(91), daysAgo(1)),
			testServiceUser(time.Time{}, daysAgo(1)),
		},
		proxyTokens: []*pb.WebhookToken{
			testProxyToken(daysAgo(5), true),
			testProxyToken(time.Time{}, false),
		},
	}
	cases := map[string]struct {
		audit       bool
		credentials map[string]any
		pointers    []string
	}{
		"audit": {
			true,
			map[string]any{"credentials_present": true, "credential_count": 4},
			[]string{"/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct"},
		},
		"trust": {
			false,
			map[string]any{"credentials_present": true},
			[]string{"/credentials/rotation_overdue_pct"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &componentsdk.Recorder{}
			out := buildAccess(src, kitNow, tc.audit, gapLog{rec: rec})
			raw, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			wantSection(t, doc, "credentials", tc.credentials)
			partial := map[string]componentsdk.Gap{}
			for _, g := range rec.Gaps() {
				if g.Status == componentsdk.GapPartial {
					partial[g.Pointer] = g
				}
			}
			if len(partial) != len(tc.pointers) {
				t.Errorf("%d partial gaps, want %d", len(partial), len(tc.pointers))
			}
			for _, pointer := range tc.pointers {
				g, ok := partial[pointer]
				if !ok {
					t.Errorf("no partial gap on %s", pointer)
					continue
				}
				if g.Code != componentsdk.CodeInvalidResponse || g.Unmeasured != 2 {
					t.Errorf("gap on %s has code %q and %d unmeasured, want invalid_response and 2", pointer, g.Code, g.Unmeasured)
				}
			}
		})
	}
}

// In a workspace with no service users, an unscoped proxy auth token is
// unrestricted and a scoped one is not. No proxy auth token has write
// access.
func TestAccessProxyTokensOnly(t *testing.T) {
	src := accessSources{
		serviceUsers: []*pb.ServiceUser{},
		proxyTokens: []*pb.WebhookToken{
			testProxyToken(daysAgo(200), false),
			testProxyToken(daysAgo(5), true),
			testProxyToken(daysAgo(5), true),
		},
	}
	doc, gaps := buildTestAccess(t, src, true)
	wantSection(t, doc, "credentials", map[string]any{
		"credentials_present": true, "credential_count": 3,
		"unrestricted_credential_count": 1, "unrestricted_pct": 34,
		"write_access_credential_count": 0, "write_access_pct": 0,
		"rotation_overdue_credential_count": 1, "rotation_overdue_pct": 34,
	})
	for _, v := range roleValues {
		wantNoGap(t, gaps, v.pointer)
	}
	wantGap(t, gaps, "/credentials/unused_pct", componentsdk.CodeUnsupported)
}

// Without proxy auth tokens, a service user never used or last used more
// than 90 days before the run counts as unused.
func TestAccessUnusedServiceUsers(t *testing.T) {
	src := accessSources{
		serviceUsers: []*pb.ServiceUser{
			testServiceUser(daysAgo(10), time.Time{}),
			testServiceUser(daysAgo(200), daysAgo(91)),
			testServiceUser(daysAgo(200), daysAgo(90)),
			testServiceUser(daysAgo(10), daysAgo(1)),
		},
		proxyTokens: []*pb.WebhookToken{},
	}
	doc, gaps := buildTestAccess(t, src, true)
	c := section(doc, "credentials")
	if c["unused_credential_count"] != 2.0 || c["unused_pct"] != 50.0 {
		t.Errorf("unused_credential_count %v, unused_pct %v; want 2 and 50", c["unused_credential_count"], c["unused_pct"])
	}
	wantNoGap(t, gaps, "/credentials/unused_pct")
}

// Below the audit level, no count is written and no count gets a gap.
func TestAccessTrustLevel(t *testing.T) {
	members := []*pb.WorkspaceMembersListItem{testMember(owner, github, daysAgo(1))}
	tokens := []*pb.WebhookToken{testProxyToken(daysAgo(1), false)}
	cases := map[string]struct {
		serviceUsers []*pb.ServiceUser
		credentials  map[string]any
	}{
		"with service users":    {[]*pb.ServiceUser{testServiceUser(daysAgo(1), daysAgo(1))}, map[string]any{"credentials_present": true, "rotation_overdue_pct": 0}},
		"without service users": {[]*pb.ServiceUser{}, map[string]any{"credentials_present": true, "unrestricted_pct": 100, "write_access_pct": 0, "rotation_overdue_pct": 0}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			doc, gaps := buildTestAccess(t, accessSources{members: members, serviceUsers: tc.serviceUsers, proxyTokens: tokens}, false)
			wantSection(t, doc, "members", map[string]any{
				"members_present": true, "sso_coverage_pct": 0, "local_members_present": true, "inactive_pct": 0,
			})
			wantSection(t, doc, "admins", map[string]any{"admins_present": true, "admin_share_pct": 100, "local_admins_present": true})
			wantSection(t, doc, "credentials", tc.credentials)
			for pointer := range gaps {
				if strings.HasSuffix(pointer, "_count") {
					t.Errorf("gap on %s, which a trust run does not write", pointer)
				}
			}
		})
	}
}

// A members list that fails leaves out sign-in, members, and admins with
// its error.
func TestAccessMembersFail(t *testing.T) {
	refused := componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("refused"))
	doc, gaps := buildTestAccess(t, accessSources{membersErr: refused}, true)
	for _, name := range []string{"sign_in", "members", "admins"} {
		if _, ok := doc[name]; ok {
			t.Errorf("%s is written, want it left out", name)
		}
	}
	for _, pointer := range []string{"/sign_in/sso_configured", "/members", "/admins"} {
		wantGap(t, gaps, pointer, componentsdk.CodePermissionDenied)
	}
}

// When one credential list fails, credentials_present is still true when
// the other list has any. The counts and percentages are left out with the
// error.
func TestAccessCredentialListFails(t *testing.T) {
	failed := componentsdk.CodeError(componentsdk.CodeVendorError, errors.New("unavailable"))
	cases := map[string]struct {
		src     accessSources
		written bool
	}{
		"service users fail, tokens listed": {accessSources{serviceUsersErr: failed, proxyTokens: []*pb.WebhookToken{testProxyToken(daysAgo(1), true)}}, true},
		"tokens fail, service users listed": {accessSources{proxyTokensErr: failed, serviceUsers: []*pb.ServiceUser{testServiceUser(daysAgo(1), daysAgo(1))}}, true},
		"service users fail, no tokens":     {accessSources{serviceUsersErr: failed, proxyTokens: []*pb.WebhookToken{}}, false},
		"both fail":                         {accessSources{serviceUsersErr: failed, proxyTokensErr: failed}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			doc, gaps := buildTestAccess(t, tc.src, true)
			if !tc.written {
				if _, ok := doc["credentials"]; ok {
					t.Errorf("credentials is written, want it left out")
				}
				wantGap(t, gaps, "/credentials", componentsdk.CodeVendorError)
				return
			}
			wantSection(t, doc, "credentials", map[string]any{"credentials_present": true})
			for _, v := range credentialValues {
				wantGap(t, gaps, v.pointer, componentsdk.CodeVendorError)
			}
		})
	}
}

// Modal has no root account and does not report connected apps, external
// members, or MFA, so those are left out of every run with an unsupported
// gap.
func TestAccessUnsupported(t *testing.T) {
	doc, gaps := buildTestAccess(t, accessSources{members: []*pb.WorkspaceMembersListItem{testMember(owner, github, daysAgo(1))}}, true)
	for _, name := range []string{"root", "connected_apps"} {
		if _, ok := doc[name]; ok {
			t.Errorf("%s is written, want it left out", name)
		}
	}
	for _, u := range accessUnsupported {
		wantGap(t, gaps, u.pointer, componentsdk.CodeUnsupported)
	}
	if doc["provider"] != "modal" || doc["system_type"] != "platform" {
		t.Errorf("provider %v, system_type %v; want modal and platform", doc["provider"], doc["system_type"])
	}
}

func TestParseConfigAcceptsLevelAndCollect(t *testing.T) {
	if _, err := ParseConfig(map[string]any{"level": "audit", "collect": []any{"access-posture"}}); err != nil {
		t.Errorf("ParseConfig: %v", err)
	}
	if _, err := ParseConfig(map[string]any{"workspace": "kit-workspace"}); err == nil {
		t.Error("ParseConfig accepted an unknown setting")
	}
}
