# Configuration

The collector reads a Modal workspace through Modal's API with an API token.

## 1. Create the API token

Create the token as the workspace's Owner or a Manager, since only they can list the workspace's members. With a Member's token, the collector reads everything else and leaves the members out with a `permission_denied` gap.

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

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MODAL_TOKEN_ID` | The API token's ID, which starts with `ak-`. |
| `MODAL_TOKEN_SECRET` | The API token's secret, which starts with `as-`. |

## Partial Collection and Exit Codes

The run fails only when the configuration is invalid (exit 2), when Modal rejects the token (exit 3), or when Modal's API cannot be reached (exit 4). Every other read that fails leaves its values out of `artifacts/modal.json`, and `artifacts/modal.collector-result.json` records a gap for each, with the call that failed and what to check.

This value is left out every time its condition holds:

| Value | Code | When |
|-------|------|------|
| `members` | `permission_denied` | The token belongs to a Member. |
