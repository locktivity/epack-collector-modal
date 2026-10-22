package collector

import (
	"fmt"
	"time"

	"github.com/locktivity/epack/componentsdk"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"

	"github.com/locktivity/epack-collector-modal/internal/modal"
)

// inactiveDays is how long a member can go without activity before the
// members rollup counts them as inactive.
const inactiveDays = 90

// collect signs in, then reads each part of the workspace in its own step.
// It fails only when the sign-in fails. A value it can't read after that is
// left out with a gap, never written as zero or false.
func collect(ctx componentsdk.CollectorContext, client *modal.Client) (*Output, error) {
	signIn, step := componentsdk.StartCollectorStep(ctx, "sign_in", "Sign in")
	token, err := client.TokenInfo(signIn.Context())
	step.End()
	if err != nil {
		return nil, signInError(err)
	}
	rec := componentsdk.Records(ctx)
	principal := componentsdk.Principal{Provider: "modal", Kind: "user", TenantID: token.GetWorkspaceId(), AuthMethod: componentsdk.AuthAPIToken}
	if sa := token.GetServiceUserIdentity(); sa != nil {
		principal.Kind, principal.ID = "service_user", sa.GetServiceUserId()
	} else {
		principal.ID = token.GetUserIdentity().GetUserId()
	}
	rec.SignedInAs(principal)
	gaps := gapLog{rec: rec}

	now := componentsdk.Now(ctx).UTC()
	inventories := ctx.Level().AtLeast(componentsdk.LevelAudit)
	out := &Output{
		SchemaVersion:    SchemaVersion,
		CollectedAt:      now.Format(time.RFC3339),
		CollectedAtLevel: string(ctx.Level()),
		Workspace:        Workspace{ID: token.GetWorkspaceId(), Name: token.GetWorkspaceName()},
	}

	people, step := componentsdk.StartCollectorStep(ctx, "members", "Members")
	out.Members = readMembers(people, client, gaps, now, inventories)
	step.End()

	envs, step := componentsdk.StartCollectorStep(ctx, "environments", "Environments")
	environments, listed, envErr := readEnvironments(envs, client, gaps, inventories)
	out.Environments = environments
	step.End()

	tokens, step := componentsdk.StartCollectorStep(ctx, "tokens", "Service users and proxy auth tokens")
	out.ServiceUsers = readServiceUsers(tokens, client, gaps, inventories)
	out.ProxyAuthTokens = readProxyTokens(tokens, client, gaps, listed, envErr, inventories)
	step.End()

	if envErr != nil {
		err := fmt.Errorf("the secrets and apps are listed by environment: %w", envErr)
		gaps.notCollected(err, "/secrets")
		gaps.notCollected(err, "/apps")
		return out, nil
	}
	workloads, step := componentsdk.StartCollectorStep(ctx, "workloads", "Secrets and apps")
	out.Secrets = readSecrets(workloads, client, gaps, listed, inventories)
	out.Apps = readApps(workloads, client, gaps, listed, inventories)
	step.End()
	return out, nil
}

// signInError says what to fix when the sign-in fails. The SDK gives the
// error its exit code, 3 for a token Modal rejects.
func signInError(err error) error {
	if componentsdk.Classify(err) == componentsdk.CodeAuthFailed {
		return fmt.Errorf("signing in: Modal rejected the token. Check %s and %s, and that the token has not been revoked or expired: %w", tokenIDEnv, tokenSecretEnv, err)
	}
	return fmt.Errorf("signing in: %w", err)
}

// timestamp formats seconds since the epoch as RFC 3339 in UTC. Modal
// sends 0 for a time it doesn't have, which becomes nil.
func timestamp(seconds float64) *string {
	if seconds <= 0 {
		return nil
	}
	s := time.Unix(int64(seconds), 0).UTC().Format(time.RFC3339)
	return &s
}

// optional returns nil for an empty string.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func environmentRoleName(role pb.EnvironmentRole) string {
	switch role {
	case pb.EnvironmentRole_ENVIRONMENT_ROLE_CONTRIBUTOR:
		return "contributor"
	case pb.EnvironmentRole_ENVIRONMENT_ROLE_VIEWER:
		return "viewer"
	case pb.EnvironmentRole_ENVIRONMENT_ROLE_NO_ACCESS:
		return "no_access"
	case pb.EnvironmentRole_ENVIRONMENT_ROLE_MODAL_ADMINISTERED_OBSERVER:
		return "modal_observer"
	default:
		return "other"
	}
}
