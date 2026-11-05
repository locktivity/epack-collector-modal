package collector

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// membersRefusedWarning explains a permission_denied gap on the members.
const membersRefusedWarning = "Reading members needs a token that belongs to the workspace's Owner or a Manager."

// readMembers lists the workspace's members. Their rows, sorted by email,
// appear from the audit level. It also returns the members without a
// deletion time, for the access-posture artifact, or the error the list
// failed with.
func readMembers(ctx componentsdk.CollectorContext, client *modal.Client, gaps gapLog, now time.Time, inventories bool) (*Members, []*pb.WorkspaceMembersListItem, error) {
	members, err := client.ListMembers(ctx.Context())
	if err != nil {
		gaps.notCollected(err, "/members", membersAdvice(err)...)
		return nil, nil, err
	}
	out := &Members{}
	rows := []Member{}
	live := make([]*pb.WorkspaceMembersListItem, 0, len(members))
	cutoff := inactiveCutoff(now)
	for _, m := range members {
		if m.GetDeletedAt() > 0 {
			continue
		}
		live = append(live, m)
		row := Member{
			Name:         m.GetMemberDisplayname(),
			Email:        strings.ToLower(m.GetEmail()),
			Role:         memberRoleName(m.GetMemberRole()),
			SignIn:       signInName(m.GetIdentityProviderType()),
			JoinedAt:     timestamp(m.GetJoinedAt()),
			LastActiveAt: timestamp(m.GetLastActiveAt()),
		}
		row.Inactive = before(m.GetLastActiveAt(), cutoff)
		out.TotalCount++
		switch row.Role {
		case "owner":
			out.OwnerCount++
		case "manager":
			out.ManagerCount++
		case "member":
			out.MemberCount++
		}
		switch row.SignIn {
		case "github":
			out.SignIn.GitHubCount++
		case "google":
			out.SignIn.GoogleCount++
		case "saml":
			out.SignIn.SAMLCount++
		default:
			out.SignIn.OtherCount++
		}
		if row.Inactive {
			out.InactiveCount++
		}
		rows = append(rows, row)
	}
	if inventories {
		slices.SortStableFunc(rows, func(a, b Member) int { return cmp.Or(cmp.Compare(a.Email, b.Email), cmp.Compare(a.Name, b.Name)) })
		out.Inventory = rows
	}
	return out, live, nil
}

// membersAdvice is the advice for a gap on a value from the members list.
// For a refused token, it says who can read members. The gap names the
// Manager role, which the members operation declares.
func membersAdvice(err error) []componentsdk.AdviceOption {
	if componentsdk.Classify(err) != componentsdk.CodePermissionDenied {
		return nil
	}
	return []componentsdk.AdviceOption{componentsdk.Warning(membersRefusedWarning)}
}

func memberRoleName(role pb.MemberRole) string {
	switch role {
	case pb.MemberRole_MEMBER_ROLE_OWNER:
		return "owner"
	case pb.MemberRole_MEMBER_ROLE_MANAGER:
		return "manager"
	case pb.MemberRole_MEMBER_ROLE_USER:
		return "member"
	default:
		return "other"
	}
}

func signInName(provider pb.IdentityProviderType) string {
	switch provider {
	case pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GITHUB:
		return "github"
	case pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_GOOGLE_OAUTH:
		return "google"
	case pb.IdentityProviderType_IDENTITY_PROVIDER_TYPE_SAML:
		return "saml"
	default:
		return "other"
	}
}
