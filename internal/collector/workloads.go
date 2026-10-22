package collector

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/locktivity/epack/componentsdk"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// readSecrets lists the secrets in every environment, sorted by environment,
// then name. The secrets are left out if one environment's list fails,
// since the counts would cover only part of the workspace.
func readSecrets(ctx componentsdk.CollectorContext, client *modal.Client, gaps gapLog, envs []environmentRef, inventories bool) *Secrets {
	out := &Secrets{}
	rows := []Secret{}
	for _, env := range envs {
		items, err := client.ListSecrets(ctx.Context(), env.Name)
		if err != nil {
			gaps.notCollected(fmt.Errorf("the %s environment: %w", env.Name, err), "/secrets")
			return nil
		}
		for _, item := range items {
			meta := item.GetMetadata()
			row := Secret{
				Name:        cmp.Or(meta.GetName(), item.GetLabel()),
				Environment: env.Name,
				CreatedBy:   optional(meta.GetCreationInfo().GetCreatedBy()),
				CreatedAt:   timestamp(modal.SecretCreatedAt(item)),
				LastUsedAt:  timestamp(item.GetLastUsedAt()),
				NeverUsed:   item.GetLastUsedAt() <= 0,
				Keys:        slices.Sorted(slices.Values(meta.GetKeys())),
			}
			if row.Keys == nil {
				row.Keys = []string{}
			}
			out.TotalCount++
			if row.NeverUsed {
				out.NeverUsedCount++
			}
			rows = append(rows, row)
		}
	}
	if inventories {
		slices.SortStableFunc(rows, func(a, b Secret) int {
			return cmp.Or(cmp.Compare(a.Environment, b.Environment), cmp.Compare(a.Name, b.Name))
		})
		out.Inventory = rows
	}
	return out
}

// readApps lists the apps in every environment and reads the functions of
// each deployed one, sorted by environment, then name. The apps are left
// out if a list or a deployed app's functions can't be read, since the
// counts would cover only part of the workspace.
func readApps(ctx componentsdk.CollectorContext, client *modal.Client, gaps gapLog, envs []environmentRef, inventories bool) *Apps {
	out := &Apps{}
	rows := []App{}
	for _, env := range envs {
		apps, err := client.ListApps(ctx.Context(), env.Name)
		if err != nil {
			gaps.notCollected(fmt.Errorf("the %s environment: %w", env.Name, err), "/apps")
			return nil
		}
		for _, app := range apps {
			row := App{
				Name:        app.GetName(),
				Environment: env.Name,
				State:       appStateName(app.GetState()),
				CreatedAt:   timestamp(app.GetCreatedAt()),
			}
			if app.GetState() == pb.AppState_APP_STATE_DEPLOYED {
				info, err := client.AppInfo(ctx.Context(), app.GetAppId())
				if err != nil {
					gaps.notCollected(fmt.Errorf("the %s app in the %s environment: %w", app.GetName(), env.Name, err), "/apps")
					return nil
				}
				web, unauthenticated, scheduled := countFunctions(info)
				row.WebEndpoints, row.UnauthenticatedEndpoints, row.ScheduledFunctions = &web, &unauthenticated, &scheduled
				out.DeployedCount++
				out.WebEndpointCount += web
				out.UnauthenticatedEndpointCount += unauthenticated
				out.ScheduledFunctionCount += scheduled
			}
			rows = append(rows, row)
		}
	}
	if inventories {
		slices.SortStableFunc(rows, func(a, b App) int {
			return cmp.Or(cmp.Compare(a.Environment, b.Environment), cmp.Compare(a.Name, b.Name))
		})
		out.Inventory = rows
	}
	return out
}

// countFunctions counts an app's web functions, how many of them need no
// proxy auth, and its scheduled functions. A web function counts as needing
// no proxy auth unless its summary says it requires it, since that is
// Modal's default.
func countFunctions(info *pb.AppGetInfoResponse) (web, unauthenticated, scheduled int) {
	for _, f := range info.GetFunctionInfoSummaries() {
		if f.GetWebFunction() {
			web++
			if !f.GetRequiresProxyAuth() {
				unauthenticated++
			}
		}
		if f.HasSchedule() {
			scheduled++
		}
	}
	return web, unauthenticated, scheduled
}

func appStateName(state pb.AppState) string {
	switch state {
	case pb.AppState_APP_STATE_DEPLOYED:
		return "deployed"
	case pb.AppState_APP_STATE_EPHEMERAL:
		return "ephemeral"
	case pb.AppState_APP_STATE_DETACHED, pb.AppState_APP_STATE_DETACHED_DISCONNECTED:
		return "detached"
	case pb.AppState_APP_STATE_STOPPING:
		return "stopping"
	case pb.AppState_APP_STATE_STOPPED:
		return "stopped"
	case pb.AppState_APP_STATE_INITIALIZING:
		return "initializing"
	case pb.AppState_APP_STATE_DISABLED:
		return "disabled"
	default:
		return "other"
	}
}
