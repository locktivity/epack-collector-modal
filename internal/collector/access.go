package collector

import (
	"cmp"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/locktivity/epack/componentsdk"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
)

// accessSchema is the schema ID of the access-posture artifact. The SDK
// holds its schema, and docs/schema/methods.json says how each value is
// measured.
const accessSchema = "evidencepack/access-posture@v1"

// accessPath is where the access-posture artifact sits in the pack.
var accessPath = componentsdk.ArtifactPath(collectorName, accessSchema)

// AccessPosture is the evidencepack/access-posture@v1 artifact for the
// workspace. It covers sign-in, members, admins, and machine credentials.
// The counts are written from the audit level. A section whose list could
// not be read is left out with a gap, and so is each value Modal does not
// report.
type AccessPosture struct {
	SchemaVersion string             `json:"schema_version"`
	CollectedAt   string             `json:"collected_at"`
	Provider      string             `json:"provider"`
	SystemType    string             `json:"system_type"`
	SignIn        *AccessSignIn      `json:"sign_in,omitempty"`
	Members       *AccessMembers     `json:"members,omitempty"`
	Admins        *AccessAdmins      `json:"admins,omitempty"`
	Credentials   *AccessCredentials `json:"credentials,omitempty"`
}

// AccessSignIn is how members sign in. It comes from the members list,
// since Modal does not report the workspace's SSO settings.
type AccessSignIn struct {
	SSOConfigured bool `json:"sso_configured"`
}

// AccessMembers rolls up the members. A member who signs in through SAML
// SSO counts as an SSO member, and every other member as a local one. Each
// Modal account has one identity provider and no password, so the two never
// overlap.
type AccessMembers struct {
	MembersPresent      bool `json:"members_present"`
	MemberCount         *int `json:"member_count,omitempty"`
	SSOMemberCount      *int `json:"sso_member_count,omitempty"`
	SSOCoveragePct      pct  `json:"sso_coverage_pct,omitzero"`
	LocalMembersPresent bool `json:"local_members_present"`
	LocalMemberCount    *int `json:"local_member_count,omitempty"`
	InactiveMemberCount *int `json:"inactive_member_count,omitempty"`
	InactivePct         pct  `json:"inactive_pct,omitzero"`
}

// AccessAdmins rolls up the Owner, the Managers, and the Members no
// restricted environment limits. A value is left out when it depends on a
// Member whose roles could not be read.
type AccessAdmins struct {
	AdminsPresent      *bool `json:"admins_present,omitempty"`
	AdminCount         *int  `json:"admin_count,omitempty"`
	AdminSharePct      pct   `json:"admin_share_pct,omitzero"`
	LocalAdminsPresent *bool `json:"local_admins_present,omitempty"`
	LocalAdminCount    *int  `json:"local_admin_count,omitempty"`
}

// AccessCredentials rolls up the service users and proxy auth tokens.
// When one of the two lists could not be read, only credentials_present is
// written, and only when the other list has any.
type AccessCredentials struct {
	CredentialsPresent             bool `json:"credentials_present"`
	CredentialCount                *int `json:"credential_count,omitempty"`
	UnusedCredentialCount          *int `json:"unused_credential_count,omitempty"`
	UnusedPct                      pct  `json:"unused_pct,omitzero"`
	UnrestrictedCredentialCount    *int `json:"unrestricted_credential_count,omitempty"`
	UnrestrictedPct                pct  `json:"unrestricted_pct,omitzero"`
	WriteAccessCredentialCount     *int `json:"write_access_credential_count,omitempty"`
	WriteAccessPct                 pct  `json:"write_access_pct,omitzero"`
	RotationOverdueCredentialCount *int `json:"rotation_overdue_credential_count,omitempty"`
	RotationOverduePct             pct  `json:"rotation_overdue_pct,omitzero"`
}

// pct is a percentage in the access-posture artifact. It is left out when
// it was not read, null over an empty population, and otherwise a whole
// number.
type pct struct {
	value *int
	read  bool
}

// IsZero reports whether the percentage was not read, for omitzero.
func (p pct) IsZero() bool { return !p.read }

// MarshalJSON writes the percentage, or null.
func (p pct) MarshalJSON() ([]byte, error) { return json.Marshal(p.value) }

// percent is count as a percentage of total, rounded as the schema says.
func percent(count, total int, rounding componentsdk.Rounding) pct {
	return pct{value: componentsdk.Percent(count, total, rounding), read: true}
}

// accessSources holds each list the access-posture artifact is built from,
// or the error the list failed with.
type accessSources struct {
	members         []*pb.WorkspaceMembersListItem
	membersErr      error
	environments    environmentList
	environmentsErr error
	serviceUsers    []*pb.ServiceUser
	serviceUsersErr error
	proxyTokens     []*pb.WebhookToken
	proxyTokensErr  error
}

// unsupportedValue is a value Modal does not report, with the reason its
// gap gives. audit marks a count, which is written from the audit level.
type unsupportedValue struct {
	pointer, reason string
	audit           bool
}

// The details of the gaps on values Modal does not report, and on the
// values that need roles the collector does not read.
const (
	noSSORequirement  = "Modal's API does not report the workspace's Require SSO setting."
	noMFASetting      = "Members sign in to Modal with GitHub, Google, or SAML SSO, and Modal has no MFA setting of its own."
	noSCIM            = "Modal does not report whether member accounts are provisioned through SCIM."
	noExternalMembers = "Modal does not mark any member as coming from outside the organization."
	noMemberMFA       = "Modal does not report whether a member who signs in with GitHub or Google has MFA."
	noRootAccount     = "Modal has no built-in root account. The workspace's Owner is a member and counts as an admin."
	noConnectedApps   = "Modal does not report third-party apps with access to the workspace."
	noExpiry          = "Modal's lists of service users and proxy auth tokens do not report when a token expires."
	noProxyTokenUse   = "Modal does not report when a proxy auth token was last used."
	rolesNotRead      = "Modal's EnvironmentGetRoles call reports each service user's role in an environment, which this collector does not read for every environment."
)

// errNoCreatedAt is why the credentials overdue for rotation are left out
// when a credential has no creation time.
var errNoCreatedAt = componentsdk.CodeError(componentsdk.CodeInvalidResponse,
	errors.New("a service user or proxy auth token in the response has no creation time"))

// accessUnsupported lists the values Modal does not report, in any
// workspace.
var accessUnsupported = []unsupportedValue{
	{"/sign_in/sso_required", noSSORequirement, false},
	{"/sign_in/mfa_required", noMFASetting, false},
	{"/sign_in/scim_enabled", noSCIM, false},
	{"/members/external_members_present", noExternalMembers, false},
	{"/members/external_member_count", noExternalMembers, true},
	{"/members/local_mfa_member_count", noMemberMFA, true},
	{"/members/local_mfa_coverage_pct", noMemberMFA, false},
	{"/admins/local_mfa_admin_count", noMemberMFA, true},
	{"/admins/local_admin_mfa_coverage_pct", noMemberMFA, false},
	{"/root", noRootAccount, false},
	{"/connected_apps", noConnectedApps, false},
	{"/credentials/never_expiring_credential_count", noExpiry, true},
	{"/credentials/never_expiring_pct", noExpiry, false},
}

// accessValue is a value in the access-posture artifact. audit marks a
// count, which is written from the audit level.
type accessValue struct {
	pointer string
	audit   bool
}

// credentialValues lists the credential counts and percentages, which are
// left out when either list could not be read.
var credentialValues = []accessValue{
	{"/credentials/credential_count", true},
	{"/credentials/unused_credential_count", true},
	{"/credentials/unused_pct", false},
	{"/credentials/unrestricted_credential_count", true},
	{"/credentials/unrestricted_pct", false},
	{"/credentials/write_access_credential_count", true},
	{"/credentials/write_access_pct", false},
	{"/credentials/rotation_overdue_credential_count", true},
	{"/credentials/rotation_overdue_pct", false},
}

// roleValues lists the credential values that depend on each service
// user's environment roles. They are left out in a workspace with service
// users.
var roleValues = []accessValue{
	{"/credentials/unrestricted_credential_count", true},
	{"/credentials/unrestricted_pct", false},
	{"/credentials/write_access_credential_count", true},
	{"/credentials/write_access_pct", false},
}

// buildAccess builds the access-posture artifact from src. audit is true
// from the audit level, where the counts are written. Each value it leaves
// out gets a gap.
func buildAccess(src accessSources, now time.Time, audit bool, gaps gapLog) *AccessPosture {
	out := &AccessPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   now.Format(time.RFC3339),
		Provider:      "modal",
		SystemType:    "platform",
	}
	cutoff := inactiveCutoff(now)
	if err := src.membersErr; err != nil {
		opts := membersAdvice(err)
		gaps.access(err, "/sign_in/sso_configured", opts...)
		gaps.access(err, "/members", opts...)
		gaps.access(err, "/admins", opts...)
	} else {
		out.SignIn, out.Members, out.Admins = accessPeople(src, cutoff, audit, gaps)
	}
	out.Credentials = accessCredentials(src, cutoff, audit, gaps)
	for _, u := range accessUnsupported {
		if u.audit && !audit {
			continue
		}
		gaps.unsupported(u.pointer, u.reason)
	}
	return out
}

// accessPeople rolls up the members, who are listed without a deletion
// time. The Owner and the Managers are admins. A Member is an admin too when
// no restricted environment limits them, since they can then change or
// delete any app, secret or volume in the workspace. When that can't be
// told for a Member, because an environment's roles could not be read, the
// admin values that depend on them are left out with a partial gap.
func accessPeople(src accessSources, cutoff time.Time, audit bool, gaps gapLog) (*AccessSignIn, *AccessMembers, *AccessAdmins) {
	var total, sso, inactive, admins, localAdmins, unknown, localUnknown int
	var unknownErr error
	for _, m := range src.members {
		total++
		saml := m.GetIdentityProviderType() == pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_SAML
		if saml {
			sso++
		}
		if before(m.GetLastActiveAt(), cutoff) {
			inactive++
		}
		admin := true
		if m.GetMemberRole() == pb.MemberRole_MEMBER_ROLE_USER {
			var err error
			admin, err = unrestricted(m.GetUserId(), src.environments, src.environmentsErr)
			if err != nil {
				unknown++
				if !saml {
					localUnknown++
				}
				unknownErr = cmp.Or(unknownErr, err)
				continue
			}
		} else if m.GetMemberRole() != pb.MemberRole_MEMBER_ROLE_OWNER && m.GetMemberRole() != pb.MemberRole_MEMBER_ROLE_MANAGER {
			admin = false
		}
		if admin {
			admins++
			if !saml {
				localAdmins++
			}
		}
	}
	local := total - sso
	signIn := &AccessSignIn{SSOConfigured: sso > 0}
	people := &AccessMembers{
		MembersPresent:      total > 0,
		MemberCount:         atAudit(total, audit),
		SSOMemberCount:      atAudit(sso, audit),
		SSOCoveragePct:      percent(sso, total, componentsdk.RoundDown),
		LocalMembersPresent: local > 0,
		LocalMemberCount:    atAudit(local, audit),
		InactiveMemberCount: atAudit(inactive, audit),
		InactivePct:         percent(inactive, total, componentsdk.RoundUp),
	}
	admin := &AccessAdmins{}
	if admins > 0 || unknown == 0 {
		admin.AdminsPresent = new(admins > 0)
	} else {
		gaps.partial("/admins/admins_present", unknown, unknownErr)
	}
	if localAdmins > 0 || localUnknown == 0 {
		admin.LocalAdminsPresent = new(localAdmins > 0)
	} else {
		gaps.partial("/admins/local_admins_present", localUnknown, unknownErr)
	}
	if unknown == 0 {
		admin.AdminCount = atAudit(admins, audit)
		admin.AdminSharePct = percent(admins, total, componentsdk.RoundUp)
	} else {
		gaps.partial("/admins/admin_share_pct", unknown, unknownErr)
		if audit {
			gaps.partial("/admins/admin_count", unknown, unknownErr)
		}
	}
	if localUnknown == 0 {
		admin.LocalAdminCount = atAudit(localAdmins, audit)
	} else if audit {
		gaps.partial("/admins/local_admin_count", localUnknown, unknownErr)
	}
	return signIn, people, admin
}

// unrestricted reports whether the Member with userID can change or delete
// anything in every environment in envs, listed with envsErr. A Member can
// in an environment that is not restricted. In a restricted one, they can
// only with the Contributor role, either their own or the environment's
// default member role. The error says why it can't be told.
func unrestricted(userID string, envs environmentList, envsErr error) (bool, error) {
	if envsErr != nil {
		return false, envsErr
	}
	var unread error
	for _, item := range envs.items {
		if !item.GetIsManaged() {
			continue
		}
		roles := envs.roles[item.GetEnvironmentId()]
		if roles.err != nil {
			unread = cmp.Or(unread, roles.err)
			continue
		}
		if memberEnvironmentRole(userID, item, roles.resp) != pb.EnvironmentRole_ENVIRONMENT_ROLE_CONTRIBUTOR {
			return false, nil
		}
	}
	return unread == nil, unread
}

// memberEnvironmentRole is the role the Member with userID has in the
// restricted environment item, whose roles are resp: the role resp gives
// them, or the environment's default member role when resp does not name
// them.
func memberEnvironmentRole(userID string, item *pb.EnvironmentListItem, resp *pb.EnvironmentGetRolesResponse) pb.EnvironmentRole {
	for _, p := range resp.GetPrincipalRoles() {
		if p.GetUserId() == userID && p.GetRole() != pb.EnvironmentRole_ENVIRONMENT_ROLE_UNSPECIFIED {
			return p.GetRole()
		}
	}
	if resp.HasDefaultMemberRole() {
		return resp.GetDefaultMemberRole()
	}
	return item.GetDefaultMemberRole()
}

// hasMemberRole reports whether any of members has the Member role, which
// makes them an admin only when no restricted environment limits them.
func hasMemberRole(members []*pb.WorkspaceMembersListItem) bool {
	return slices.ContainsFunc(members, func(m *pb.WorkspaceMembersListItem) bool {
		return m.GetMemberRole() == pb.MemberRole_MEMBER_ROLE_USER
	})
}

// accessCredentials rolls up the service users and proxy auth tokens. A
// service user's access comes from its role in each environment, and those
// roles are not read for every environment. The unrestricted credentials
// and those with write access are therefore counted only in a workspace
// without service users. There, an unscoped proxy auth token is
// unrestricted, and no credential has write access, since a proxy auth
// token is good only for calling web endpoints. Modal does not report when
// a proxy auth token was used, so the unused credentials are counted only
// in a workspace without one. When a credential has no creation time, the
// credentials overdue for rotation are left out with a partial gap.
func accessCredentials(src accessSources, cutoff time.Time, audit bool, gaps gapLog) *AccessCredentials {
	if err := cmp.Or(src.serviceUsersErr, src.proxyTokensErr); err != nil {
		if len(src.serviceUsers)+len(src.proxyTokens) == 0 {
			gaps.access(err, "/credentials")
			return nil
		}
		for _, v := range credentialValues {
			if v.audit && !audit {
				continue
			}
			gaps.access(err, v.pointer)
		}
		return &AccessCredentials{CredentialsPresent: true}
	}
	var total, unused, unrestricted int
	var rotation rotationCount
	for _, u := range src.serviceUsers {
		total++
		if before(u.GetLastUsedAt(), cutoff) {
			unused++
		}
		rotation.add(u.GetCreatedAt(), cutoff)
	}
	for _, t := range src.proxyTokens {
		total++
		if !t.GetScoped() {
			unrestricted++
		}
		rotation.add(t.GetCreatedAt(), cutoff)
	}
	out := &AccessCredentials{
		CredentialsPresent: total > 0,
		CredentialCount:    atAudit(total, audit),
	}
	if rotation.unknown > 0 {
		gaps.partial("/credentials/rotation_overdue_pct", rotation.unknown, errNoCreatedAt)
		if audit {
			gaps.partial("/credentials/rotation_overdue_credential_count", rotation.unknown, errNoCreatedAt)
		}
	} else {
		out.RotationOverdueCredentialCount = atAudit(rotation.overdue, audit)
		out.RotationOverduePct = percent(rotation.overdue, total, componentsdk.RoundUp)
	}
	if len(src.serviceUsers) > 0 {
		for _, v := range roleValues {
			if v.audit && !audit {
				continue
			}
			gaps.notRead(v.pointer, rolesNotRead)
		}
	} else {
		out.UnrestrictedCredentialCount = atAudit(unrestricted, audit)
		out.UnrestrictedPct = percent(unrestricted, total, componentsdk.RoundUp)
		out.WriteAccessCredentialCount = atAudit(0, audit)
		out.WriteAccessPct = percent(0, total, componentsdk.RoundUp)
	}
	if len(src.proxyTokens) > 0 {
		gaps.unsupported("/credentials/unused_pct", noProxyTokenUse)
		if audit {
			gaps.unsupported("/credentials/unused_credential_count", noProxyTokenUse)
		}
		return out
	}
	out.UnusedCredentialCount = atAudit(unused, audit)
	out.UnusedPct = percent(unused, total, componentsdk.RoundUp)
	return out
}

// rotationCount counts the credentials created more than 90 days before the
// run. unknown counts those with no creation time, which Modal sends as 0.
type rotationCount struct {
	overdue, unknown int
}

// add counts a credential created at created, in seconds since the epoch.
func (r *rotationCount) add(created float64, cutoff time.Time) {
	switch {
	case created <= 0:
		r.unknown++
	case before(created, cutoff):
		r.overdue++
	}
}

// atAudit returns n from the audit level, where the access-posture schema
// writes counts, and nil below it.
func atAudit(n int, audit bool) *int {
	if !audit {
		return nil
	}
	return &n
}
