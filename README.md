# MCP Rewrite Proxy

A proxy that sits in front of an OAuth-protected MCP server. It signs in to that upstream server and changes what AI agents see: tool names, titles, descriptions, annotations, parameters and schemas, plus the server's instructions. Agents connect to the proxy instead of the upstream.

It runs as a Docker container on your own servers, behind Cloudflare Tunnel, on as many identical nodes as you like. **There is no database, and nodes share nothing at runtime.** All they have in common is a config file and a secret.

```
                                  ┌── node 1: [ proxy ⇄ cloudflared ] + own upstream login ──┐
agents ─▶ Cloudflare edge ─tunnel─┼── node 2: [ proxy ⇄ cloudflared ] + own upstream login ──┼──▶ upstream MCP
 you  ─▶ (mcp-proxy.example.com)  └── node N: …                                               ┘
                                         ▲ same config/proxy.config.json and PROXY_SECRET on every node
```

## Where everything lives

| What | Where | Shared? |
|---|---|---|
| Tool and server edits, agent revocations | `config/proxy.config.json` | Same file on every node; you deploy it. Nodes reload it within seconds. |
| Settings and secrets | `.env` | Same on every node. |
| Agents' OAuth registrations, codes and tokens | Nowhere. Each one is an encrypted, self-contained value that any node can check with `PROXY_SECRET`. | No storage needed. |
| Upstream login | Each node's own `/data` volume | **Per node.** Each node signs in once with `mcp-proxy login`. |

The upstream login is per node because most OAuth servers **rotate** refresh tokens: each refresh replaces the old token. With one shared login, the first node to refresh would break it for the others. With one login each, nodes never need to coordinate.

## How the high availability works

- **Each node is one container** running the proxy and its own cloudflared connector. All nodes use the same tunnel token, so each one is a replica of the same tunnel. Cloudflare spreads requests across connected replicas.
- **A node is only in rotation while it can serve.** The proxy supervises cloudflared and keeps the connector up only while the node holds a working upstream login. A node that has never signed in, or whose login the upstream revoked, takes itself out; the other nodes carry the traffic until you run `mcp-proxy login` on it again. The node refreshes its token ahead of expiry, so a revoked login is usually caught before an agent's request runs into it.
- **Any node can serve any request.** Agent registration, consent, the code exchange, refreshes and MCP calls can each land on a different node. Admin sessions are signed cookies, and the sign-in landing page works from any node.
- **Graceful drain on `docker stop`.** The node takes down its tunnel connector first, so new requests go to other nodes. cloudflared lets in-flight requests finish. Then the HTTP server drains and the container exits. Rolling updates one node at a time drop nothing.

## Set up

1. **Tunnel.** In Cloudflare Zero Trust, go to Networks → Tunnels and create a tunnel. Copy its token. Add a public hostname (for example `mcp-proxy.example.com`) with service **`http://localhost:8080`**. cloudflared runs inside the proxy container, so `localhost` is the proxy itself.
2. **On every node**, put the same three things next to each other:
   - [`docker-compose.yml`](docker-compose.yml)
   - `.env` copied from [`.env.example`](.env.example): `PUBLIC_URL` (the tunnel hostname), `UPSTREAM_URL`, `TUNNEL_TOKEN`, `ADMIN_PASSWORD` and `PROXY_SECRET` (generate it with `openssl rand -hex 32`)
   - `config/proxy.config.json`, starting from the [one in this repo](config/proxy.config.json)
3. **Start** each node:

   ```bash
   docker compose up -d --build
   ```

   To build once instead, push the image to your registry and set `IMAGE` in `.env` on each node.
4. **Sign each node in to the upstream:**

   ```bash
   docker compose exec proxy mcp-proxy login
   ```

   Open the link it prints and sign in. You'll land on a page on your proxy's hostname that shows a code (any node can serve that page). Paste the code back into the terminal. The node joins the tunnel within seconds. `mcp-proxy status` shows a node's login.
5. **Connect agents.** Add `https://mcp-proxy.example.com/mcp` as a remote MCP server. When the agent opens the authorization page, sign in with the admin password and approve it.

## Editing tools

Open `https://mcp-proxy.example.com/admin`. The page fetches the live tool list with the login of whichever node served it. For each tool it shows the upstream original, your editable fields, and a preview of exactly what agents will see. When you're done, click **Download config** and replace `config/proxy.config.json` on every node by copying it, using rsync, or committing it to the repo you deploy from. Each node reloads the file within about two seconds. If a file is invalid (for example, two tools renamed to the same name), the node keeps serving the last good config and the admin page shows why.

| Level | Options |
|---|---|
| Tool | hide; rename; title; description (`{{original}}` inserts the upstream text); each annotation hint |
| Parameter | rename; description; required or optional; **hidden** (any value the agent sends is dropped); **fixed value** (hidden, and always sent upstream); **default** (filled in when the agent leaves it out); JSON Merge Patch on its schema (`enum`, `type`, `minimum`, `items`, …) |
| Escape hatches | merge patches on `inputSchema`, on `outputSchema` (`null` removes it), and on the **whole tool definition**, which can reach any field, including `_meta` and `icons` |
| Server | instructions; `serverInfo`; allowlist mode (new upstream tools stay hidden until you edit them) |

Calls are mapped back to the upstream names, with fixed and default values filled in. If an agent calls a hidden tool, or a tool's old name after a rename, the proxy refuses the call itself and it never reaches the upstream. The file format is documented in [`src/rewrite.ts`](src/rewrite.ts) and [`src/config-file.ts`](src/config-file.ts).

## Agent auth

The proxy is its own OAuth 2.1 authorization server, implementing the MCP authorization profile:

- discovery through RFC 9728 and RFC 8414 metadata
- RFC 7591 dynamic client registration
- authorization codes with PKCE (S256 only)
- refresh tokens
- RFC 8707 resource binding and the RFC 9207 `iss` parameter

Claude, Claude Code, Cursor and other MCP clients connect with it as they would to any MCP server. Approving an agent requires the admin password, so nobody else can borrow your upstream account. Approvals are remembered in your browser for 30 days.

**Nothing is stored.** A client ID is the client's registration, encrypted. Codes and tokens are encrypted claims, and a confidential client's secret is derived from its ID. Everything uses AES-256-GCM with keys derived from `PROXY_SECRET`, and each kind of value is bound to its purpose, so a refresh token can't be used as an access token. The consequences:

- **Lifetimes:** access tokens last 1 hour. Refresh tokens last 30 days, extended on each use, up to 90 days after approval, after which the agent asks again. Authorization codes last 60 seconds and are single-use on the node that redeems them. Replaying a code on another node within those 60 seconds would still need the PKCE verifier.
- **Revoking:** a single token can't be revoked before it expires. Revoke in the config file instead, which takes effect on every node within seconds:

  ```json
  "agents": {
    "revoked": ["3f1c9a0d2b7e4c51"],
    "revokeIssuedBefore": "2026-10-13T00:00:00Z"
  }
  ```

  - `revoked` lists client fingerprints. A client's fingerprint appears on its consent page and in the logs.
  - `revokeIssuedBefore` refuses every approval granted before that time.
  - Changing `PROXY_SECRET` revokes everything at once.
- **Rotating the secret without logging agents out:** set the new `PROXY_SECRET` and put the old one in `PROXY_SECRET_PREVIOUS` for 30 days.
- **Headless agents** can send a static key from `API_KEYS` as `Authorization: Bearer <key>`. This sits outside the MCP OAuth profile, so it is off unless you set the key.
- **Admin login** is limited to 10 failed attempts per IP per 15 minutes on each node. For more protection, put `/admin*` and `/authorize` behind Cloudflare Access.

## Upstream auth

`mcp-proxy login` follows MCP authorization:

1. Discovery: a 401 challenge, then RFC 9728 protected resource metadata, then RFC 8414 / OIDC authorization server metadata. Older servers that use the default `/authorize` path are also supported.
2. A client is chosen: a pre-registered client (`UPSTREAM_CLIENT_ID`), a Client ID Metadata Document, or dynamic registration.
3. Sign-in uses PKCE (S256) with the RFC 8707 `resource` parameter, and RFC 9207 `iss` checking.

The redirect URI is `PUBLIC_URL/upstream-callback`. Register that URL if your upstream requires a pre-registered OAuth app.

## Settings

| Name | Required | Purpose |
|---|---|---|
| `PUBLIC_URL` | yes | Public origin (the tunnel hostname). Every OAuth URL the proxy publishes is built from it, never from the container's address. |
| `UPSTREAM_URL` | yes | Upstream MCP endpoint (Streamable HTTP). |
| `ADMIN_PASSWORD` | yes | Password for `/admin` and for approving agents. |
| `PROXY_SECRET` | yes | 32+ characters. Same on every node. |
| `TUNNEL_TOKEN` | for tunnel | Runs the node's own cloudflared connector. Leave it unset to serve on `PORT` directly, for example behind another proxy. |
| `PROXY_SECRET_PREVIOUS` | | Old secret(s), comma-separated, still accepted during a rotation. |
| `UPSTREAM_CLIENT_ID` / `UPSTREAM_CLIENT_SECRET` | | For upstreams without dynamic registration, such as a GitHub OAuth app. |
| `UPSTREAM_SCOPES` | | Space-separated scopes. Defaults to what the upstream advertises (plus `offline_access` when it is supported). |
| `UPSTREAM_SEND_RESOURCE` | | `false` for authorization servers that reject the RFC 8707 `resource` parameter. |
| `UPSTREAM_AUTH_SERVER_OVERRIDES` | | JSON merged over the discovered authorization server metadata. |
| `API_KEYS` | | Comma-separated static bearer keys (16+ characters each). |
| `PROXY_NAME` | | Name shown on the admin, consent and sign-in pages. |
| `CONFIG_PATH`, `DATA_DIR`, `PORT`, `DRAIN_TIMEOUT_MS`, `TUNNEL_GRACE_SECONDS` | | Defaults: `/config/proxy.config.json`, `/data`, 8080, 30000 and 25. |

Every setting also accepts a `*_FILE` variant, such as `ADMIN_PASSWORD_FILE=/run/secrets/admin_password`. Mount the config **directory**, not the file, so an atomically replaced file is picked up. The health endpoints are `GET /healthz` (the process is alive; this is the Docker healthcheck) and `GET /readyz` (the node holds an upstream login and is serving).

## Develop and test

```bash
npm install
```

```bash
npm test
```

Runs the unit tests for the rewrite engine, the SSE handling, the sealed tokens and the OAuth server.

```bash
npm run test:e2e
```

Starts [`docker-compose.test.yml`](docker-compose.test.yml): a mock OAuth-protected upstream (with rotating refresh tokens) and two proxy nodes that share only a config directory. Every flow hops between the two nodes. The test covers:

- `mcp-proxy login` on each node
- the agent OAuth flow
- config reloads, including a broken file being rejected
- agent revocation
- each node refreshing its own login
- the upstream revoking one node's login, which takes that node out of rotation
- re-login
- a graceful drain

Node B runs a stand-in cloudflared ([`test/fake-cloudflared.sh`](test/fake-cloudflared.sh)) so tunnel supervision can be checked without a Cloudflare account. Set `KEEP=1` to leave the cluster running afterwards.

## Limits

- One upstream per deployment. Run another deployment for each additional upstream.
- You sign in to the upstream once per node, and again on a node if the upstream revokes its login.
- Only the Streamable HTTP transport is supported upstream, not the legacy HTTP+SSE transport.
- Tool **results** pass through unchanged. Rewriting what tools return would go in `src/messages.ts`.
- When a node is removed from rotation, long-lived SSE streams on it end after the drain timeout, and agents reconnect through another node.
