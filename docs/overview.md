epack-collector-modal collects evidence of who can reach a Modal workspace and what the workspace exposes to the internet.

## What it collects

From Modal's API, with a token that belongs to the workspace's Owner or a Manager:

- **Members**, with each member's role, how they sign in, and when they were last active. A member with no activity in 90 days counts as inactive.
- **Environments**, and who holds a role in each restricted environment.
- **Service users**, with when each was last used. Only the Team and Enterprise plans have service users.
- **Proxy auth tokens**, and the environments each scoped token works in.
- **Secrets** in every environment, with the names of their keys and when each was last used.
- **Apps** in every environment. For each deployed app, the collector counts its web endpoints, the endpoints anyone can call without a proxy auth token, and its scheduled functions.

## Access posture

`artifacts/modal.access-posture.json` describes access to the workspace in the shared `evidencepack/access-posture@v1` format. It is built from the members, service users, and proxy auth tokens, with no other calls.

- **Sign-in.** `sso_configured` is true when any member signs in through SAML SSO.
- **Members.** A member who signs in through SAML SSO counts as an SSO member. A member who signs in with GitHub or Google counts as signing in without SSO, even if the workspace requires SSO, since Modal's API does not report that setting. Each Modal account has one way to sign in and no password, so an SSO member can't sign in without SSO.
- **Admins.** The Owner and the Managers.
- **Machine credentials.** Service users and proxy auth tokens. A credential created more than 90 days ago counts as overdue for rotation. In a workspace without service users, a proxy auth token that works in every environment counts as unrestricted. No proxy auth token counts as having write access, since it is good only for calling web endpoints.

## Not collected

Modal offers the following through its API, and the collector does not read them.

- **Member API tokens.** Every API token the workspace's members hold, with its expiry and when it was last used. The machine credentials in the access-posture file are service users and proxy auth tokens only.
- **Servers and Endpoints.** Modal Servers and Endpoints take web requests at their own URLs, and a Server or a Dedicated Endpoint can be set to accept requests without a proxy auth token. The collector's counts of web endpoints include only Web Functions.

## What it never collects

- Secret values. The collector reads only the names of a secret's keys.
- The secrets of API tokens and proxy auth tokens.
- Member names and emails below the `audit` level.

## Values Modal does not report

An environment with no setting of its own for blocking unauthenticated web endpoints follows the workspace default. Modal's API does not report that default, so `blocks_unauthenticated` is null for that environment.

Modal's API does not report these access-posture values either. Each one is left out of every run with an `unsupported` gap:

- Whether the workspace requires SSO, and whether it provisions accounts through SCIM.
- MFA. Members sign in with GitHub, Google, or SAML SSO, and Modal has no MFA setting of its own.
- Whether a member comes from outside the organization.
- When a service user's token or a proxy auth token expires. A service user's token can be given an expiry, but Modal's lists of service users and proxy auth tokens don't include it.
- Connected apps. Modal also has no root account.

Modal does not report when a proxy auth token was last used. In a workspace with proxy auth tokens, the unused credentials are left out with an `unsupported` gap.

## Values the collector does not read

A service user's access comes from its role in each environment. Modal reports these roles, but the collector reads them only in restricted environments, from the `audit` level. In a workspace with service users, the unrestricted credentials and those with write access are left out with a `not_read` gap.

## Artifacts

- `artifacts/modal.details.json`, described by [docs/schema/v1.0.0.json](schema/v1.0.0.json).
- `artifacts/modal.access-posture.json`, in the `evidencepack/access-posture@v1` format. [docs/schema/methods.json](schema/methods.json) says how each of its values is measured.
- `artifacts/modal.collector-result.json`, which records each value left out and why, the run's steps, and its calls.

See [levels.md](levels.md) for what each collection level adds and [examples.md](examples.md) for sample output.
