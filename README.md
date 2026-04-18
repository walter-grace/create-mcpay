# create-mcpay

A reusable Cloudflare Worker template for pay-per-call agent gateways. Spin up a fully-featured agent API — auth, billing, reputation — in ~2 minutes.

**mcpay** — because every call costs a few mcents (1 mcent = 1/1000¢). Agents pay in crypto via [x402](https://www.x402.org), you keep the revenue.

## Quickstart

```bash
npx create-mcpay my-api
cd my-api
npm install
wrangler secret put ADMIN_KEY       # random 32-hex; required for /v1/admin/mint
wrangler deploy                     # Durable Object migration runs automatically
```

Mint your first key:

```bash
curl -X POST https://<your-worker>.workers.dev/v1/admin/mint \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"balance_mcents": 10000, "scopes": ["example","read"]}'
# → {"ok":true,"key":"mcp_...","balance_mcents":10000,"scopes":["example","read"]}
```

Use it:

```bash
curl -X POST https://<your-worker>.workers.dev/v1/example \
  -H "Authorization: Bearer mcp_..." \
  -H "Content-Type: application/json" \
  -d '{"message":"hello"}'
```

## Security posture (v0.3.0, whitehat-audited twice)

- **Bearer tokens stored HASHED** (SHA-256). Raw tokens live only at mint time + in the holder's memory. A KV/DO dump exposes no live keys.
- **Atomic charging via Durable Object** with `blockConcurrencyWhile` — no TOCTOU overdraft under burst traffic.
- **Default-deny scopes** — a key minted without an explicit `scopes` array cannot call any paid endpoint. No implicit all-access.
- **Admin mint**: `timingSafeEqual` on the admin key, `crypto.getRandomValues` for the token, required `scopes`, `MAX_MINT_MCENTS` ceiling ($1,000 default).
- **Validate-before-charge** — handlers parse and shape-check the body before debiting. Malformed requests return 400 with `"note":"no charge applied"`.
- **No CORS on `/v1/admin/*`** — a compromised browser tab can't mint keys even with a leaked admin key.
- **Bounded body reads** (16 KB default) to prevent memory DoS.

See `src/template.ts` header comment for the full list.

## Architecture

```
┌──────────────┐    Bearer mcp_<hex>    ┌────────────────────────────────┐
│  External    │───────────────────────▶│ Cloudflare Worker (this repo)  │
│  Agent       │                        │   /v1/example  (paid, 100mc)   │
└──────────────┘                        │   /v1/admin/mint (admin-only)  │
                                         │                                │
                                         │   ┌────────────────────────┐   │
                                         │   │ LeaderboardDO          │   │
                                         │   │  - atomic charging     │   │
                                         │   │  - stores hashed keys  │   │
                                         │   │  - blockConcurrency…   │   │
                                         │   └────────────────────────┘   │
                                         └────────────────────────────────┘
```

## Extending with your own paid endpoint

```ts
async function handleMyTool(req: Request, env: Env): Promise<Response> {
  // 1. Validate body first — no charge on malformed requests.
  const raw = await req.text();
  if (raw.length > 16 * 1024) return error(413, "body too large");
  let body: any;
  try { body = JSON.parse(raw); } catch { body = null; }
  if (!body || typeof body.query !== "string") {
    return error(400, 'missing "query"', { note: "no charge applied" });
  }

  // 2. Auth + charge. Atomic via the Durable Object.
  const auth = await authAndCharge(req, env, 250, "mytool");
  if (auth instanceof Response) return auth;

  // 3. Do the work.
  const result = await doTheActualThing(body.query);
  return json({ ok: true, result, balance_mcents: auth.record.balance_mcents });
}
```

Register it in the router:

```ts
if (p === "/v1/mytool" && req.method === "POST") return handleMyTool(req, env);
```

Add to `CallType`, `PRICE_MCENTS`, `XP_AWARD`, `SCOPE_FOR`, plus a scope string. The template's `SCOPE_FOR` table is the single source of truth — every paid handler routes through it.

## What's NOT in the template (by design)

- **x402 signup**, **leaderboard UI**, **MCP server**, **Agent Readiness `.well-known` routes** — these are product-specific; see [data-label-factory](https://github.com/walter-grace/data-label-factory)'s `agent-gateway/` for a reference that bolts them on.
- **Refund policy** — depends on your failure modes. DLF's reference has a 5xx + rate-capped refund policy you can adapt.
- **Rate limiting on `/v1/admin/mint`** — use Cloudflare's `[[unsafe.bindings]]` rate-limiter or a DO counter. The template assumes admin is trusted.

## Changelog

- **0.3.0** — SHA-256-hashed token storage (was: raw bearer as KV key), atomic charging via Durable Object (was: TOCTOU-prone KV rmw), admin mint balance ceiling, bounded body reads, `mcp_` service-namespaced key prefix, 503 on admin when unset (no timing oracle), no CORS on admin paths. Second whitehat audit clean.
- **0.2.0** — default-deny scopes, opinionated admin mint route, validate-before-charge in example, hoisted `projectName` in scaffolder, flat 404, `X-Admin-Key` removed from CORS preflight.
- **0.1.0** — initial release.

## License

MIT. Fork, remix, commercialize.
