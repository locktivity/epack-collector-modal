epack-collector-modal collects evidence of who can reach a Modal workspace and what the workspace exposes to the internet.

## What it collects

From Modal's API, with a token that belongs to the workspace's Owner or a Manager:

- **Members**, with each member's role, how they sign in, and when they were last active. A member with no activity in 90 days counts as inactive.
- **Environments**, and who holds a role in each restricted environment.
- **Service users**, with when each was last used. Only the Team and Enterprise plans have service users.
- **Proxy auth tokens**, and the environments each scoped token works in.
- **Secrets** in every environment, with the names of their keys and when each was last used.
- **Apps** in every environment. For each deployed app, the collector counts its web endpoints, the endpoints anyone can call without a proxy auth token, and its scheduled functions.

## What it never collects

- Secret values. The collector reads only the names of a secret's keys.
- The secrets of API tokens and proxy auth tokens.
- Member names and emails below the `audit` level.

## Values Modal does not report

An environment with no setting of its own for blocking unauthenticated web endpoints follows the workspace default. Modal's API does not report that default, so `blocks_unauthenticated` is null for that environment.

## Artifacts

- `artifacts/modal.json`, described by [docs/schema/v1.0.0.json](schema/v1.0.0.json).
- `artifacts/modal.collector-result.json`, which records each value left out and why, the run's steps, and its calls.

See [levels.md](levels.md) for what each collection level adds and [examples.md](examples.md) for sample output.
