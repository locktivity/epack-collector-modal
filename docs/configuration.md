# Configuration

The collector reads a Modal workspace through Modal's API with an API token.

## 1. Create the API token

Create the token as the workspace's Owner or a Manager, since only they can list the workspace's members and service users. With a Member's token, the members and the service users are left out with a `permission_denied` gap. The sign-in, members, and admins in `artifacts/modal.access-posture.json` come from the members list, so they are left out too. The credential counts and percentages there need the service users, so they are also left out.

1. Sign in to Modal as the Owner or a Manager.
2. In **Settings**, under **API Tokens**, create a token for the workspace.
3. Keep the token ID and the token secret for step 2.

A Modal API token can do anything its user can, so a Manager's token can also change the workspace and its members.

## 2. Configure epack

```yaml
collectors:
  modal:
    source: locktivity/epack-collector-modal@^0.1
    config:
      level: audit
    secrets:
      - MODAL_TOKEN_ID
      - MODAL_TOKEN_SECRET
```

```bash
export MODAL_TOKEN_ID=YOUR-TOKEN-ID MODAL_TOKEN_SECRET=YOUR-TOKEN-SECRET
```

The collector reads the workspace the token belongs to.

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `level` | No | `trust` (the default), `audit`, or `internal`. See [levels.md](levels.md). |
| `collect` | No | The kinds of evidence to collect, from `access-posture` and `details`. Defaults to both. |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MODAL_TOKEN_ID` | The API token's ID, which starts with `ak-`. |
| `MODAL_TOKEN_SECRET` | The API token's secret, which starts with `as-`. |

## Partial Collection and Exit Codes

The run fails only when the configuration is invalid (exit 2), when Modal rejects the token (exit 3), or when Modal's API cannot be reached (exit 4). Every other read that fails leaves its values out of `artifacts/modal.details.json` and `artifacts/modal.access-posture.json`. `artifacts/modal.collector-result.json` records a gap for each, with the call that failed and what to check.

This value is left out every time its condition holds:

| Value | Code | When |
|-------|------|------|
| `members` and `service_users` in `artifacts/modal.details.json` | `permission_denied` | The token belongs to a Member. |
| `sign_in`, `members`, and `admins` in `artifacts/modal.access-posture.json` | `permission_denied` | The token belongs to a Member. |
| The counts and percentages under `credentials` in `artifacts/modal.access-posture.json` | `permission_denied` | The token belongs to a Member. |
| `environments`, `secrets`, `apps`, and each scoped proxy auth token's `environments` in `artifacts/modal.details.json` | `permission_denied` | The token belongs to a Member with No Access to every environment, so Modal lists none. |
| `unused_pct` and `unused_credential_count` in `artifacts/modal.access-posture.json` | `unsupported` | The workspace has a proxy auth token. |
| `unrestricted_pct`, `write_access_pct`, and their counts in `artifacts/modal.access-posture.json` | `not_read` | The workspace has a service user. |
