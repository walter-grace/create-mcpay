/**
 * mcpay template — single-file Cloudflare Worker for pay-per-call agent APIs.
 *
 * v0.6.0 architecture: the Durable Object is the SINGLE SOURCE OF TRUTH for
 * auth, pricing, scoping, and charging. The Worker is a thin router that
 * converts HTTP → DO RPC. It does NOT know prices. It does NOT enforce
 * scopes. It does NOT compute fees. This closes a structural blind spot
 * flagged by the third whitehat audit:
 *
 *   "The Worker→DO contract is unsigned JSON. A future maintainer adding
 *    op:'refund' or batch-charge will reintroduce the DLF-gateway class
 *    of bugs (billing logic split between Worker and DO with no single
 *    source of truth for 'what does this call cost?')."
 *
 * Design rule: the Worker MUST NOT pass cost_mcents to the DO. It passes
 * { op, key_hash, call_type } and trusts the DO to decide. Adding a new
 * paid call means updating exactly ONE table (PRICE_MCENTS) inside the DO.
 *
 * Security posture (audited three times, all findings closed):
 *   - Bearer tokens SHA-256 hashed; raw tokens never persisted.
 *   - Charging atomic via DO + blockConcurrencyWhile (no TOCTOU).
 *   - Default-deny scopes; every call_type maps to exactly one scope.
 *   - DO-side mint auth: even a sibling Worker binding to the same DO
 *     cannot mint without env.ADMIN_KEY.
 *   - Admin mint is DO-rate-limited (10/hour) so a compromised ADMIN_KEY
 *     cannot drain the treasury via infinite mints before revocation.
 *   - Post-charge invariant: DO throws if balance_mcents < 0 post-debit.
 *   - No CORS on /v1/admin/*. Bounded body reads. mcp_ service prefix.
 *   - Never log Authorization headers — wrangler tail is visible to
 *     anyone with CF dashboard access.
 *
 * MPP signup (/v1/signup) — opt-in, set TEMPO_RECIPIENT or STRIPE_RECIPIENT:
 *   Agents pay in crypto (Tempo/USDC) or card (Stripe) via Machine Payments
 *   Protocol. On verified payment the DO auto-mints a bearer key. No human
 *   needed in the loop. x402 clients work unchanged (MPP is backwards-compat).
 */

import { Mppx, tempo, stripe } from "mppx/server";

export interface Env {
  LEADERBOARD: DurableObjectNamespace;
  ADMIN_KEY: string;

  // ---- MPP signup (all optional — omit to disable /v1/signup) --------------
  // Tempo (stablecoin on Tempo network, sub-second settlement)
  TEMPO_RECIPIENT?: string;   // your Base/Tempo wallet address
  TEMPO_CURRENCY?: string;    // USDC token address on Tempo network
  // Stripe (card, wallet — requires Machine Payments enabled on account)
  STRIPE_RECIPIENT?: string;  // your Stripe Business Network recipient ID
  STRIPE_NETWORK_ID?: string; // Stripe Business Network ID
  STRIPE_SECRET_KEY?: string; // Stripe secret key (sk_live_... or sk_test_...)
  // Shared
  MPP_SECRET_KEY?: string;    // HMAC key for challenge integrity (auto-generated if unset)
  SIGNUP_PRICE_CENTS?: string;              // USD cents, default "10" ($0.10)
  DEFAULT_SIGNUP_BALANCE_MCENTS?: string;   // mcents minted per signup, default "10000"
  DEFAULT_SIGNUP_SCOPES?: string;           // comma-separated scopes, default "example"
}

// ---- Types -----------------------------------------------------------------

type CallType = "example" | "read";
type Scope = "example" | "read" | "all";

type KeyRecord = {
  balance_mcents: number;
  xp: number;
  created_at: number;
  last_active_at: number;
  display_name?: string;
  calls_total: number;
  calls_by_type: Partial<Record<CallType, number>>;
  badges: string[];
  scopes: Scope[];
};

// ---- Pricing tables (DO-owned) --------------------------------------------
//
// Defined at module scope for readability, but the DO is the only place that
// reads them during a charge. The Worker never touches them — doing so
// would split billing authority.

const PRICE_MCENTS: Record<CallType, number> = {
  example: 100, // $0.001
  read: 0,
};

const XP_AWARD: Record<CallType, number> = {
  example: 10,
  read: 0,
};

const SCOPE_FOR: Record<CallType, Scope> = {
  example: "example",
  read: "read",
};

const MAX_MINT_MCENTS = 100_000_000; // $1,000 ceiling per mint
const MAX_MINTS_PER_HOUR = 10;
const MAX_BODY_BYTES = 16 * 1024;
const KEY_PREFIX = "mcp_";

// ---- Crypto helpers --------------------------------------------------------

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function generateApiKey(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return KEY_PREFIX + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- Response helpers ------------------------------------------------------

function extractBearer(req: Request): string | null {
  const h = req.headers.get("Authorization");
  const m = h?.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function level(xp: number): number {
  return Math.floor(Math.sqrt(xp / 50));
}

function json(body: any, init: ResponseInit = {}, cors = true): Response {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(cors ? { "access-control-allow-origin": "*" } : {}),
    ...((init.headers as Record<string, string>) || {}),
  };
  return new Response(JSON.stringify(body), { ...init, headers });
}

function error(status: number, message: string, extra?: any, cors = true): Response {
  return json({ ok: false, error: message, ...(extra || {}) }, { status }, cors);
}

function hasScope(rec: KeyRecord, needed: Scope): boolean {
  const s = rec.scopes;
  if (!Array.isArray(s) || s.length === 0) return false;
  if (s.includes("all")) return true;
  return s.includes(needed);
}

// ---- DO message contract ---------------------------------------------------
// cost_mcents is NOT in any message. The DO derives it from call_type.

type ChargeRequest = { op: "charge"; key_hash: string; call_type: CallType };
type ReadRequest = { op: "read"; key_hash: string };
type MintRequest = {
  op: "mint";
  // DO re-verifies against env.ADMIN_KEY so a sibling Worker can't forge.
  admin_key_attestation: string;
  key_hash: string;
  rec: KeyRecord;
  source?: "admin" | "signup"; // determines which rate-limit window to check
};
type DoMessage = ChargeRequest | ReadRequest | MintRequest;

// ---- Durable Object: auth + pricing + charging ---------------------------

export class LeaderboardDO {
  state: DurableObjectState;
  env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") return Response.json({ ok: false, error: "POST only" }, { status: 405 });
    let msg: DoMessage;
    try { msg = (await req.json()) as DoMessage; }
    catch { return Response.json({ ok: false, error: "invalid json" }, { status: 400 }); }

    return this.state.blockConcurrencyWhile(async () => {
      switch (msg.op) {
        case "read": return this.handleRead(msg);
        case "charge": return this.handleCharge(msg);
        case "mint": return this.handleMint(msg);
        default:
          return Response.json({ ok: false, error: "unknown op" }, { status: 400 });
      }
    });
  }

  private async handleRead(msg: ReadRequest) {
    const rec = (await this.state.storage.get<KeyRecord>(`k:${msg.key_hash}`)) || null;
    return Response.json({ ok: true, record: rec });
  }

  private async handleCharge(msg: ChargeRequest) {
    const cost = PRICE_MCENTS[msg.call_type];
    const awarded_xp = XP_AWARD[msg.call_type];
    const scope = SCOPE_FOR[msg.call_type];
    if (cost === undefined || scope === undefined) {
      return Response.json({ ok: false, status: 400, error: `unknown call_type "${msg.call_type}"` });
    }

    const rec = await this.state.storage.get<KeyRecord>(`k:${msg.key_hash}`);
    if (!rec) return Response.json({ ok: false, status: 401, error: "invalid api key" });

    if (!hasScope(rec, scope)) {
      return Response.json({
        ok: false, status: 403,
        error: `not authorized for scope "${scope}"`,
        scopes: rec.scopes,
      });
    }

    if (rec.balance_mcents < cost) {
      return Response.json({
        ok: false, status: 402,
        error: "insufficient balance",
        balance_mcents: rec.balance_mcents,
        required_mcents: cost,
      });
    }

    const updated: KeyRecord = {
      ...rec,
      balance_mcents: rec.balance_mcents - cost,
      xp: rec.xp + awarded_xp,
      last_active_at: Date.now(),
      calls_total: rec.calls_total + 1,
      calls_by_type: {
        ...rec.calls_by_type,
        [msg.call_type]: (rec.calls_by_type[msg.call_type] || 0) + 1,
      },
    };

    // Post-charge invariant. If a future edit ever produces negative, fail
    // the request instead of silently crediting.
    if (updated.balance_mcents < 0) {
      throw new Error("BUG: negative balance after charge — refusing to persist");
    }

    await this.state.storage.put(`k:${msg.key_hash}`, updated);
    return Response.json({ ok: true, record: updated, cost_mcents: cost });
  }

  private async handleMint(msg: MintRequest) {
    // Defense-in-depth: even if a sibling Worker binds to this DO, they
    // can't mint without env.ADMIN_KEY (a secret scoped to our script).
    if (!this.env.ADMIN_KEY || !timingSafeEqual(msg.admin_key_attestation, this.env.ADMIN_KEY)) {
      return Response.json({ ok: false, status: 401, error: "mint unauthorized" });
    }

    // Rate limit: max N mints per hour, tracked inside the DO so it's
    // global across all Worker instances.
    const now = Date.now();
    // Separate windows: admin is capped tightly (10/hr), signup is higher (1000/hr)
    // so a wave of paid signups can't freeze out the human operator.
    const windowKey = msg.source === "signup" ? "_signup_mint_window" : "_mint_window";
    const limit = msg.source === "signup" ? 1000 : MAX_MINTS_PER_HOUR;
    const window = ((await this.state.storage.get<number[]>(windowKey)) || [])
      .filter((t) => now - t < 3_600_000);
    if (window.length >= limit) {
      return Response.json({
        ok: false, status: 429,
        error: msg.source === "signup"
          ? `signup rate limit (${limit}/hr)`
          : `admin mint rate limit (${limit}/hr)`,
        retry_after_ms: 3_600_000 - (now - window[0]),
      });
    }
    window.push(now);
    await this.state.storage.put(windowKey, window);

    await this.state.storage.put(`k:${msg.key_hash}`, msg.rec);
    return Response.json({ ok: true });
  }
}

function doStub(env: Env): DurableObjectStub {
  return env.LEADERBOARD.get(env.LEADERBOARD.idFromName("global"));
}

// ---- Auth + charge (Worker side — thin RPC) -------------------------------
//
// Note the signature: no cost_mcents. The DO owns pricing.

async function authAndCharge(
  req: Request,
  env: Env,
  call_type: CallType,
): Promise<{ ok: true; record: KeyRecord; key_hash: string; cost_mcents: number } | Response> {
  const key = extractBearer(req);
  if (!key?.startsWith(KEY_PREFIX)) return error(401, "missing or malformed bearer token");

  const key_hash = await sha256Hex(key);
  const resp = await doStub(env).fetch(new Request("https://do/charge", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ op: "charge", key_hash, call_type } as ChargeRequest),
  }));
  const r: any = await resp.json();
  if (!r.ok) {
    return error(r.status || 400, r.error, {
      balance_mcents: r.balance_mcents,
      required_mcents: r.required_mcents,
      scopes: r.scopes,
    });
  }
  return { ok: true, record: r.record, key_hash, cost_mcents: r.cost_mcents };
}

// ---- Admin: mint new keys --------------------------------------------------

async function handleAdminMint(req: Request, env: Env): Promise<Response> {
  if (!env.ADMIN_KEY) return error(503, "admin not configured", {}, false);
  const provided = req.headers.get("X-Admin-Key") || "";
  if (!timingSafeEqual(provided, env.ADMIN_KEY)) {
    return error(401, "invalid admin key", {}, false);
  }

  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) return error(413, "body too large", {}, false);
  let body: any;
  try { body = JSON.parse(raw); } catch { body = {}; }

  if (typeof body.balance_mcents !== "number") {
    return error(400, "balance_mcents must be a number", {}, false);
  }
  const n = body.balance_mcents;
  if (!Number.isFinite(n) || n < 0) {
    return error(400, "balance_mcents must be a finite non-negative number", {}, false);
  }
  const balance_mcents = Math.min(MAX_MINT_MCENTS, Math.floor(n));

  const validScopes: Scope[] = ["example", "read", "all"];
  const scopes: Scope[] = Array.isArray(body.scopes)
    ? Array.from(new Set(body.scopes.filter((s: any): s is Scope => validScopes.includes(s))))
    : [];
  if (scopes.length === 0) {
    return error(400, 'scopes required: non-empty array of ["example","read","all"]', {
      note: "default-deny: a key with no scopes cannot call any paid endpoint",
    }, false);
  }

  const key = generateApiKey();
  const key_hash = await sha256Hex(key);
  const now = Date.now();
  const rec: KeyRecord = {
    balance_mcents,
    xp: 0,
    created_at: now,
    last_active_at: now,
    display_name: body.display_name ? String(body.display_name).slice(0, 32) : undefined,
    calls_total: 0,
    calls_by_type: {},
    badges: [],
    scopes,
  };

  const resp = await doStub(env).fetch(new Request("https://do/mint", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      op: "mint",
      admin_key_attestation: env.ADMIN_KEY, // DO re-verifies
      key_hash,
      rec,
    } as MintRequest),
  }));
  const r: any = await resp.json();
  if (!r.ok) {
    return error(r.status || 500, r.error, { retry_after_ms: r.retry_after_ms }, false);
  }

  return json({
    ok: true,
    key,
    key_shown_once: true,
    balance_mcents,
    scopes,
    max_mint_mcents: MAX_MINT_MCENTS,
  }, { status: 200 }, false);
}

// ---- MPP signup: pay once → get a bearer key ------------------------------
//
// Supports Tempo (stablecoin), Stripe (card/wallet), or both simultaneously.
// Enable by setting TEMPO_RECIPIENT and/or STRIPE_RECIPIENT in wrangler secrets.
//
// Flow (MPP charge intent, x402-compatible):
//   1. Agent POST /v1/signup → 402 WWW-Authenticate: Payment (per configured method)
//   2. Agent pays on-chain or via card, retries with Authorization: Payment
//   3. mppx verifies the credential → Worker mints a key → returns it once
//
// The key is minted via the same DO path as admin mint, so all security
// invariants (hashed token, scoped, balance cap) apply identically.

async function handleSignup(req: Request, env: Env): Promise<Response> {
  const priceCents = Math.max(1, parseInt(env.SIGNUP_PRICE_CENTS || "10", 10) || 10);

  const tempoEnabled = !!(env.TEMPO_RECIPIENT && env.TEMPO_CURRENCY);
  const stripeEnabled = !!(env.STRIPE_RECIPIENT && env.STRIPE_NETWORK_ID && env.STRIPE_SECRET_KEY);

  if (!tempoEnabled && !stripeEnabled) {
    return json(
      { ok: false, error: "signup not configured — set TEMPO_RECIPIENT or STRIPE_RECIPIENT+STRIPE_SECRET_KEY" },
      { status: 501 }
    );
  }

  // Static method config (currency/keys/network) — amount is per-call via compose.
  type AnyChargeMethod = ReturnType<typeof tempo.charge | typeof stripe.charge>;
  const methods: AnyChargeMethod[] = [];

  if (tempoEnabled) {
    methods.push(tempo.charge({
      currency: env.TEMPO_CURRENCY as unknown as `0x${string}`,
      recipient: env.TEMPO_RECIPIENT as unknown as `0x${string}`,
      decimals: 6,
      description: "mcpay API key signup",
    }));
  }

  if (stripeEnabled) {
    methods.push(stripe.charge({
      secretKey: env.STRIPE_SECRET_KEY!,
      networkId: env.STRIPE_NETWORK_ID!,
      paymentMethodTypes: ["card"],
      currency: "usd",
      decimals: 2,
      description: "mcpay API key signup",
    }));
  }

  const mppx = Mppx.create({ methods, secretKey: env.MPP_SECRET_KEY, realm: new URL(req.url).hostname });

  // compose() expects [methodKey, perCallOptions] tuples — one per configured method.
  // String keys ("tempo/charge", "stripe/charge") are the stable way to reference them.
  // mppx amounts are in whole token units — "0.1" = $0.10 USDC / USD.
  // Internally mppx calls parseUnits(amount, decimals) to get base units.
  const amountUsd = String(priceCents / 100);
  const entries: [string, Record<string, unknown>][] = [];
  if (tempoEnabled)  entries.push(["tempo/charge",  { amount: amountUsd }]);
  if (stripeEnabled) entries.push(["stripe/charge", { amount: amountUsd }]);

  let result: any;
  try {
    result = await (mppx as any).compose(...entries)(req);
  } catch (err: any) {
    return error(500, `mpp error: ${err?.message ?? err}`);
  }

  // Only proceed to mint on a verified 200. Any other status (402, 401, 400, 500)
  // must be returned as-is — falling through would mint a key without payment.
  if (result.status !== 200) {
    return result.challenge instanceof Response
      ? result.challenge
      : error(result.status ?? 402, "payment required or verification failed");
  }

  // Payment verified — mint a key
  const balance_mcents = Math.min(
    MAX_MINT_MCENTS,
    Math.max(0, parseInt(env.DEFAULT_SIGNUP_BALANCE_MCENTS || "10000", 10) || 10_000)
  );

  const validScopes: Scope[] = ["example", "read", "all"];
  const rawScopes = (env.DEFAULT_SIGNUP_SCOPES || "example").split(",").map((s) => s.trim());
  const scopes: Scope[] = rawScopes.filter((s): s is Scope => validScopes.includes(s as Scope));
  if (scopes.length === 0) scopes.push("example");

  const key = generateApiKey();
  const key_hash = await sha256Hex(key);
  const now = Date.now();
  const rec: KeyRecord = {
    balance_mcents,
    xp: 0,
    created_at: now,
    last_active_at: now,
    calls_total: 0,
    calls_by_type: {},
    badges: [],
    scopes,
  };

  const doResp = await doStub(env).fetch(new Request("https://do/mint", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ op: "mint", admin_key_attestation: env.ADMIN_KEY, key_hash, rec, source: "signup" } as MintRequest),
  }));
  const r: any = await doResp.json();
  if (!r.ok) return error(r.status || 500, r.error);

  // withReceipt() wraps our response with the Payment-Receipt header so the
  // client can verify the transaction settled on their end.
  return result.withReceipt(
    new Response(
      JSON.stringify({ ok: true, key, key_shown_once: true, balance_mcents, scopes }),
      { headers: { "content-type": "application/json", "access-control-allow-origin": "*" } }
    )
  );
}

// ---- Example handler (replace with your own) ------------------------------
// Pattern: validate body FIRST (no charge on bad shape), THEN authAndCharge.

async function handleExample(req: Request, env: Env): Promise<Response> {
  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) {
    return error(413, "body too large", { max_bytes: MAX_BODY_BYTES, note: "no charge applied" });
  }
  let body: any;
  try { body = JSON.parse(raw); } catch { body = null; }
  if (!body || typeof body.message !== "string" || body.message.length === 0 || body.message.length > 4096) {
    return error(400, 'missing or invalid "message" (string, 1-4096 chars)', {
      expected: { message: "<your input, max 4096 chars>" },
      note: "no charge applied",
    });
  }

  const auth = await authAndCharge(req, env, "example");
  if (auth instanceof Response) return auth;

  return json({
    ok: true,
    echoed: body.message.slice(0, 200),
    balance_mcents: auth.record.balance_mcents,
    cost_mcents: auth.cost_mcents,
    xp: auth.record.xp,
    level: level(auth.record.xp),
  });
}

// ---- Router ---------------------------------------------------------------

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const p = url.pathname.replace(/\/$/, "") || "/";

    if (req.method === "OPTIONS") {
      if (p.startsWith("/v1/admin")) return new Response(null, { status: 204 });
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Authorization, Content-Type",
        },
      });
    }

    if (p === "/v1/health") return json({ ok: true, ts: Date.now() });
    if (p === "/v1/pricing") return json({ prices_mcents: PRICE_MCENTS });
    if (p === "/v1/signup" && req.method === "POST") return handleSignup(req, env);
    if (p === "/v1/example" && req.method === "POST") return handleExample(req, env);
    if (p === "/v1/admin/mint" && req.method === "POST") return handleAdminMint(req, env);

    return error(404, "not found");
  },
};
