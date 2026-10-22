package collector

import (
	"time"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-modal/docs/schema"
	"github.com/locktivity/epack-collector-modal/internal/modal"
)

const (
	// artifactPath is where the collector's artifact sits in the pack.
	artifactPath = "artifacts/modal.json"

	// The variables the token arrives in, which epack.yaml lists under
	// secrets. They are the names Modal's own tools read.
	tokenIDEnv     = "MODAL_TOKEN_ID"
	tokenSecretEnv = "MODAL_TOKEN_SECRET"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        "modal",
		Version:     version,
		Commit:      commit,
		Description: "Who can reach a Modal workspace and what it exposes: members, environments, service users, proxy auth tokens, secrets, and apps with their web endpoints.",
		Timeout:     10 * time.Minute,
		Schemas:     map[string][]byte{artifactPath: schema.Artifact},
		TraceMap:    schema.TraceMap,
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	if _, err := ParseConfig(ctx.Config()); err != nil {
		return componentsdk.NewConfigError("%w", err)
	}
	tokenID, tokenSecret := ctx.Secret(tokenIDEnv), ctx.Secret(tokenSecretEnv)
	if tokenID == "" || tokenSecret == "" {
		return componentsdk.NewConfigError("%s and %s are required", tokenIDEnv, tokenSecretEnv)
	}

	httpClient := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts:   []string{modal.APIHost},
		CredentialHeaders: modal.CredentialHeaders,
		ClassifyResponse:  modal.Classify,
		ClassifySuccess:   true,
		VendorCode:        modal.VendorCode,
	})
	output, err := collect(ctx, modal.NewClient(httpClient, tokenID, tokenSecret))
	if err != nil {
		return err
	}

	return ctx.Emit([]componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(artifactPath, output, componentsdk.ArtifactMeta{
			DisplayName: "Modal workspace access",
			Description: "Members, environments, service users, proxy auth tokens, secrets, and apps with their web endpoints",
		}),
	})
}
