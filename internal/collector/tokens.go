package collector

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// readServiceUsers lists the workspace's service users, sorted by name.
func readServiceUsers(ctx componentsdk.CollectorContext, client *modal.Client, gaps gapLog, inventories bool) *ServiceUsers {
	users, err := client.ListServiceUsers(ctx.Context())
	if err != nil {
		gaps.notCollected(err, "/service_users")
		return nil
	}
	out := &ServiceUsers{TotalCount: len(users)}
	rows := make([]ServiceUser, 0, len(users))
	for _, u := range users {
		row := ServiceUser{
			Name:       u.GetName(),
			CreatedBy:  optional(u.GetCreatedBy()),
			CreatedAt:  timestamp(u.GetCreatedAt()),
			LastUsedAt: timestamp(u.GetLastUsedAt()),
			NeverUsed:  u.GetLastUsedAt() <= 0,
		}
		if row.NeverUsed {
			out.NeverUsedCount++
		}
		rows = append(rows, row)
	}
	if inventories {
		slices.SortStableFunc(rows, func(a, b ServiceUser) int { return cmp.Compare(a.Name, b.Name) })
		out.Inventory = rows
	}
	return out
}

// readProxyTokens lists the workspace's proxy auth tokens, sorted by name,
// and the environments each scoped one is limited to. envErr is the error
// the environment list failed with, if it did, since a scoped token's
// environments are named from that list.
func readProxyTokens(ctx componentsdk.CollectorContext, client *modal.Client, gaps gapLog, envs []environmentRef, envErr error, inventories bool) *ProxyAuthTokens {
	tokens, err := client.ListProxyTokens(ctx.Context())
	if err != nil {
		gaps.notCollected(err, "/proxy_auth_tokens")
		return nil
	}
	out := &ProxyAuthTokens{TotalCount: len(tokens)}
	rows := make([]ProxyAuthToken, 0, len(tokens))
	for _, t := range tokens {
		row := ProxyAuthToken{
			Name:      t.GetName(),
			CreatedBy: optional(t.GetCreatedBy().GetUsername()),
			CreatedAt: timestamp(t.GetCreatedAt()),
			Scoped:    t.GetScoped(),
		}
		if !row.Scoped {
			out.UnscopedCount++
		}
		rows = append(rows, row)
	}
	if !inventories {
		return out
	}
	order := make([]int, len(rows))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(rows[a].Name, rows[b].Name) })
	sorted := make([]ProxyAuthToken, len(rows))
	for at, i := range order {
		row := rows[i]
		if row.Scoped {
			row.Environments = scopedEnvironments(ctx, client, gaps, tokens[i].GetTokenId(), envs, envErr, at)
		}
		sorted[at] = row
	}
	out.Inventory = sorted
	return out
}

// scopedEnvironments lists the environments a scoped proxy auth token
// works in, by name, sorted.
func scopedEnvironments(ctx componentsdk.CollectorContext, client *modal.Client, gaps gapLog, tokenID string, envs []environmentRef, envErr error, index int) []string {
	pointer := fmt.Sprintf("/proxy_auth_tokens/inventory/%d/environments", index)
	if envErr != nil {
		gaps.notCollected(fmt.Errorf("a scoped token's environments are named from the environment list: %w", envErr), pointer)
		return nil
	}
	ids, err := client.ProxyTokenEnvironments(ctx.Context(), tokenID)
	if err != nil {
		gaps.notCollected(err, pointer)
		return nil
	}
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, environmentName(envs, id))
	}
	slices.Sort(names)
	return names
}
