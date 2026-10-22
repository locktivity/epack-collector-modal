# Collection Levels

The `level` config key sets how much detail the collector writes. The levels are cumulative: each one holds everything the level below it holds.

| Level | What `artifacts/modal.json` holds |
|-------|-----------------------------------|
| `trust` (the default) | The workspace's ID and name, and counts. Members by role, by how they sign in, and inactive. Environments and restricted environments. Service users and secrets, with how many were never used. Proxy auth tokens, with how many work in every environment. Deployed apps, their web endpoints, the endpoints that need no proxy auth token, and their scheduled functions. No emails, and no names of members, tokens, secrets, or apps. |
| `audit` | Adds the rows behind each count: each member's name, email, role, sign-in, and last activity, and each environment's settings with who holds a role in it. Each service user and secret, with who created it and when it was last used. Each proxy auth token, with who created it and the environments it works in. Each app, with its state and its functions. A secret's row lists its key names, never their values. |
| `internal` | The same as `audit`. |

The level the collector ran at is the artifact's `collected_at_level`.
