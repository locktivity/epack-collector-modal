package collector

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/locktivity/epack/componentsdk"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// environmentRef names an environment the token can see.
type environmentRef struct {
	ID   string
	Name string
}

// readEnvironments lists the environments the token can see, and who holds
// a role in each restricted one. It returns the environments for the steps
// that read by environment, or the list's error when it failed.
func readEnvironments(ctx componentsdk.CollectorContext, client *modal.Client, gaps gapLog, inventories bool) (*Environments, []environmentRef, error) {
	items, err := client.ListEnvironments(ctx.Context())
	if err != nil {
		gaps.notCollected(err, "/environments")
		return nil, nil, err
	}
	items = slices.Clone(items)
	slices.SortStableFunc(items, func(a, b *pb.EnvironmentListItem) int { return cmp.Compare(a.GetName(), b.GetName()) })
	out := &Environments{TotalCount: len(items)}
	refs := make([]environmentRef, 0, len(items))
	rows := make([]Environment, 0, len(items))
	for i, item := range items {
		refs = append(refs, environmentRef{ID: item.GetEnvironmentId(), Name: item.GetName()})
		row := Environment{
			Name:       item.GetName(),
			Default:    item.GetDefault(),
			Restricted: item.GetIsManaged(),
			CreatedAt:  timestamp(item.GetCreatedAt()),
		}
		if item.HasDefaultMemberRole() {
			role := environmentRoleName(item.GetDefaultMemberRole())
			row.DefaultMemberRole = &role
		}
		if item.HasBlockUnauthenticatedResources() {
			blocks := item.GetBlockUnauthenticatedResources()
			row.BlocksUnauthenticated = &blocks
		}
		if row.Restricted {
			out.RestrictedCount++
			if inventories {
				row.Roles = readEnvironmentRoles(ctx, client, gaps, item, i)
			}
		}
		rows = append(rows, row)
	}
	if inventories {
		out.Inventory = rows
	}
	return out, refs, nil
}

// readEnvironmentRoles reads who holds a role of their own in a restricted
// environment, sorted by kind, then name. Members who only inherit the
// environment's default role are left out, since default_member_role
// covers them.
func readEnvironmentRoles(ctx componentsdk.CollectorContext, client *modal.Client, gaps gapLog, item *pb.EnvironmentListItem, index int) []RoleGrant {
	resp, err := client.EnvironmentRoles(ctx.Context(), item.GetEnvironmentId())
	if err != nil {
		gaps.notCollected(err, fmt.Sprintf("/environments/inventory/%d/roles", index))
		return nil
	}
	grants := []RoleGrant{}
	for _, p := range resp.GetPrincipalRoles() {
		if p.HasInheritsDefaultMemberRole() && p.GetInheritsDefaultMemberRole() {
			continue
		}
		grant := RoleGrant{Role: environmentRoleName(p.GetRole())}
		if p.GetRoleStr() != "" {
			grant.Role = p.GetRoleStr()
		}
		switch {
		case p.GetServiceUserId() != "":
			grant.Kind, grant.Principal = "service_user", p.GetServiceUserName()
		default:
			grant.Kind, grant.Principal = "member", cmp.Or(p.GetEmail(), p.GetUserName())
		}
		grants = append(grants, grant)
	}
	slices.SortStableFunc(grants, func(a, b RoleGrant) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Principal, b.Principal))
	})
	return grants
}

// environmentName returns the name of the environment with id, or the ID
// itself when the token can't see that environment.
func environmentName(refs []environmentRef, id string) string {
	for _, ref := range refs {
		if ref.ID == id {
			return ref.Name
		}
	}
	return id
}
