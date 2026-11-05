# epack-collector-modal

An epack collector that reads who can reach a Modal workspace and what it exposes: members, environments, service users, proxy auth tokens, secrets, and apps with their web endpoints.

See [docs/](docs/) for setup and the output: [configuration](docs/configuration.md), [overview](docs/overview.md), [levels](docs/levels.md), and [examples](docs/examples.md).

## Layout

| Path | Contents |
|------|----------|
| `cmd/epack-collector-modal/main.go` | The entrypoint, which runs the handler |
| `internal/collector/handler.go` | The collector's spec and handler, and the HTTP client for Modal's API |
| `internal/collector/collector.go` | The sign-in and the run's steps |
| `internal/collector/members.go` | Members |
| `internal/collector/environments.go` | Environments and the roles in restricted ones |
| `internal/collector/tokens.go` | Service users and proxy auth tokens |
| `internal/collector/access.go` | The access-posture artifact, built from the members, service users, and proxy auth tokens |
| `internal/collector/workloads.go` | Secrets and apps |
| `internal/collector/gaps.go` | Records each value the collector leaves out, and why |
| `internal/modal/client.go` | The API client, with one named operation per call |
| `docs/schema/v1.0.0.json` | The detailed artifact's JSON Schema, with the `x-epack` annotations the output checks read |
| `docs/schema/methods.json` | One sentence on how each access-posture value is measured |
| `docs/schema/trace-map.json` | The trace map, which links each field to the calls and the code behind it |

Modal's API is gRPC. The client sends each call as an HTTP/2 request through the SDK's HTTP client, with the message types from Modal's Go SDK.

## Development

```bash
make build
./epack-collector-modal --capabilities
```

## Testing

```bash
make test
```

`internal/collector/collectortest_test.go` runs the collector against canned responses: a Team workspace written by hand in `fixtures_test.go`, an empty one, and scenarios for a Member's token and a rejected token. Other scenarios cover members who all sign in through SSO, a workspace with no proxy auth tokens, one with no service users, a refused list of service users, and a `collect` key that lists one kind. The suite then makes each call fail in turn, with errors such as a 403, a timeout, or a malformed body, and checks that each value the collector could not read is left out with a gap. It also checks the output against its schemas at every collection level, and checks that no credential reaches another host or any output. `codec_test.go` lets the suite read and change Modal's protobuf bodies as JSON. `access_test.go` checks how each access-posture value is counted.

`internal/modal/client_test.go` runs calls against a local HTTP/2 server, since the canned responses carry no trailers and Modal sends a call's status in them.

### Recording the sandbox

`internal/collector/record_test.go` runs the collector once against a sandbox, a Modal workspace kept with known settings, and writes the responses to `internal/collector/testdata/recordings/modal.json`, which the suite loads as one more scenario. It reads the workspace's name and the members' addresses from `SANDBOX_MODAL_WORKSPACE`, `SANDBOX_MODAL_OWNER_EMAIL`, `SANDBOX_MODAL_MANAGER_EMAIL`, and `SANDBOX_MODAL_MEMBER_EMAIL`, and the token from the two variables the collector reads:

```bash
make record
```

The recording replaces the workspace, the members' addresses and names, and every Modal object ID with fakes, and leaves out avatar URLs and identity provider IDs. It fails rather than write a recording that still holds one of them or a credential, and `TestRecordingsScrubbed` checks the committed recording again.

### Trace map

After a change to the code, rewrite the trace map and commit the result:

```bash
make trace-map
```

CI fails when the committed map is stale, and so does `go test` when the suite finds a call or field the map lacks.

### Conformance

```bash
make conformance
```

This runs the conformance harness at the epack version `go.mod` pins, with a canary value in each variable `CONFORMANCE_SECRETS` lists in the Makefile. The canary token reaches Modal's API, which rejects it, so conformance checks that the run exits 3 and that no output prints a canary.

## CI

`.github/workflows/ci.yaml` calls epack's shared collector workflow, which runs the tests, lint, release builds, conformance, the trace map check, and govulncheck. On a pull request it also compares each scenario's output with the output of the latest release.

## Release

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow runs CI, builds binaries for linux and darwin on amd64 and arm64 with [SLSA Level 3](https://slsa.dev/spec/v1.0/levels#build-l3) provenance, and creates the GitHub release. When the repository variable `SANDBOX_RELEASE_CHECK` is `true`, the release starts as a draft, and `publish.yaml` publishes it once the sandbox check passes on the tag's commit.

## License

Apache 2.0. See [LICENSE](LICENSE).
