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

// environmentList is the environments the token can see, sorted by name,
// and the roles read in each restricted one, by environment ID.
type environmentList struct {
	items []*pb.EnvironmentListItem
	roles map[string]environmentRoles
}

// environmentRoles is the answer to the roles call for one restricted
// environment, or the call's error.
type environmentRoles struct {
	resp *pb.EnvironmentGetRolesResponse
	err  error
}

// listEnvironments lists the environments the token can see. With roles, it
// also reads who holds which role in each restricted one.
func listEnvironments(ctx componentsdk.CollectorContext, client *modal.Client, roles bool) (environmentList, error) {
	items, err := client.ListEnvironments(ctx.Context())
	if err != nil {
		return environmentList{}, err
	}
	items = slices.Clone(items)
	slices.SortStableFunc(items, func(a, b *pb.EnvironmentListItem) int { return cmp.Compare(a.GetName(), b.GetName()) })
	out := environmentList{items: items, roles: map[string]environmentRoles{}}
	if !roles {
		return out, nil
	}
	for _, item := range items {
		if item.GetIsManaged() {
			resp, err := client.EnvironmentRoles(ctx.Context(), item.GetEnvironmentId())
			out.roles[item.GetEnvironmentId()] = environmentRoles{resp: resp, err: err}
		}
	}
	return out, nil
}

// readEnvironments writes the environments in list, and with inventories,
// who holds a role in each restricted one. It returns the environments for
// the steps that read by environment.
func readEnvironments(list environmentList, gaps gapLog, inventories bool) (*Environments, []environmentRef) {
	out := &Environments{TotalCount: len(list.items)}
	refs := make([]environmentRef, 0, len(list.items))
	rows := make([]Environment, 0, len(list.items))
	for i, item := range list.items {
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
				row.Roles = roleGrants(list.roles[item.GetEnvironmentId()], gaps, i)
			}
		}
		rows = append(rows, row)
	}
	if inventories {
		out.Inventory = rows
	}
	return out, refs
}

// roleGrants lists who holds a role of their own in a restricted
// environment, the one at index, sorted by kind, then name. Members who
// only inherit the environment's default role are left out, since
// default_member_role covers them. Service users without a role assignment
// are left out too. A service user has No Access in any environment where
// it was never given a role.
func roleGrants(roles environmentRoles, gaps gapLog, index int) []RoleGrant {
	if roles.err != nil {
		gaps.notCollected(roles.err, fmt.Sprintf("/environments/inventory/%d/roles", index))
		return nil
	}
	grants := []RoleGrant{}
	for _, p := range roles.resp.GetPrincipalRoles() {
		if p.HasInheritsDefaultMemberRole() && p.GetInheritsDefaultMemberRole() {
			continue
		}
		if p.GetServiceUserId() != "" && p.HasHasRoleAssignment() && !p.GetHasRoleAssignment() {
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
