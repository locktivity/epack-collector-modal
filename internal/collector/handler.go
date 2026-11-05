package collector

import (
	"time"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-modal/docs/schema"
	"github.com/locktivity/epack-collector-modal/internal/modal"
)

const (
	// collectorName is the collector's name, which its artifact paths start
	// with.
	collectorName = "modal"

	// artifactPath is where the collector's detailed artifact sits in the
	// pack, the path componentsdk.ArtifactPath gives a file with no schema ID.
	artifactPath = "artifacts/modal.details.json"

	// The variables the token arrives in, which epack.yaml lists under
	// secrets. They are the names Modal's own tools read.
	tokenIDEnv     = "MODAL_TOKEN_ID"
	tokenSecretEnv = "MODAL_TOKEN_SECRET"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        collectorName,
		Version:     version,
		Commit:      commit,
		Description: "Who can reach a Modal workspace and what it exposes: members, environments, service users, proxy auth tokens, secrets, and apps with their web endpoints.",
		Timeout:     10 * time.Minute,
		Schemas:     map[string][]byte{artifactPath: schema.Artifact},
		Methods:     schema.Methods(),
		TraceMap:    schema.TraceMap,
		Writes:      []string{accessSchema},
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read. An artifact the collect config key
// leaves out is not emitted.
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
	output, access, err := collect(ctx, modal.NewClient(httpClient, tokenID, tokenSecret))
	if err != nil {
		return err
	}

	artifacts := []componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(artifactPath, output, componentsdk.ArtifactMeta{
			DisplayName: "Modal workspace access",
			Description: "Members, environments, service users, proxy auth tokens, secrets, and apps with their web endpoints",
		}),
	}
	if access != nil {
		artifacts = append(artifacts, componentsdk.JSONArtifact(accessPath, access, componentsdk.ArtifactMeta{
			Schema:      accessSchema,
			DisplayName: "Modal access posture",
			Description: "How members sign in, the workspace's admins, and its service users and proxy auth tokens",
		}))
	}
	return ctx.Emit(artifacts)
}
