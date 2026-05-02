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

## Security posture (v0.6.0, battle-tested across 36 attack scenarios)

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
                                         │   │ BillingDO              │   │
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

- **Leaderboard UI**, **MCP server**, **Agent Readiness `.well-known` routes** — product-specific; bolt them on top of this template once you know what you need.
- **Refund policy** — depends on your failure modes. A common pattern: refund on 5xx provider errors only, rate-capped (e.g. 5/hr/key) via a ring buffer inside the DO.
- **Rate limiting on paid endpoints** — use Cloudflare's `[[unsafe.bindings]]` rate-limiter or a DO counter. The template assumes bearer key holders are trusted up to their balance.

## MPP signup — autonomous key minting

Enable `/v1/signup` so agents self-serve keys without a human admin. Set at least one payment method's secrets:

```bash
# Tempo (stablecoin, sub-second settlement)
wrangler secret put TEMPO_RECIPIENT   # wallet to receive USDC
wrangler secret put TEMPO_CURRENCY    # USDC token address on Tempo network
wrangler secret put MPP_SECRET_KEY    # openssl rand -hex 32

# Stripe (card/wallet — Machine Payments must be enabled on your Stripe account)
wrangler secret put STRIPE_RECIPIENT
wrangler secret put STRIPE_NETWORK_ID
wrangler secret put STRIPE_SECRET_KEY

# Optional tuning (defaults shown)
wrangler secret put SIGNUP_PRICE_CENTS             # 10  ($0.10)
wrangler secret put DEFAULT_SIGNUP_BALANCE_MCENTS  # 10000 (100 calls at 100mc each)
wrangler secret put DEFAULT_SIGNUP_SCOPES          # example
```

The signup flow (MPP charge intent, x402-compatible):

```
Agent POST /v1/signup
→ 402  WWW-Authenticate: Payment ...   (one header per configured method)

Agent pays (Tempo USDC or Stripe card), retries:
→ POST /v1/signup  Authorization: Payment <credential>
→ 200  {"ok":true,"key":"mcp_...","balance_mcents":10000,"scopes":["example"]}
        Payment-Receipt: ...
```

Both methods can be active simultaneously — the agent picks whichever it supports. x402 clients work unchanged (MPP is backwards-compatible with x402).

## License

MIT. Fork, remix, commercialize.
