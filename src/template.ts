/**
 * mcpay template — single-file Cloudflare Worker for pay-per-call agent APIs.
 *
 * Reusable primitives: bearer-token auth, mcent pricing, scoped keys,
 * XP leaderboard, admin-gated key minting. Replace the `/v1/example`
 * handler with your own paid tools.
 *
 * Security posture (v0.3.0, whitehat-reviewed twice):
 *   - hasScope() is DEFAULT-DENY: undefined/empty scopes grant nothing.
 *   - Bearer tokens are stored HASHED (SHA-256). Raw tokens exist only at
 *     mint time + in the holder's memory. A KV dump exposes no live keys.
 *   - Charging is serialized through a Durable Object with
 *     blockConcurrencyWhile() — no TOCTOU overdraft.
 *   - Admin mint uses timingSafeEqual + crypto.getRandomValues + required
 *     scopes + a ceiling on balance_mcents.
 *   - /v1/admin/* responses omit CORS wildcard so a browser can't mint keys
 *     via a compromised tab.
 *   - Admin endpoint returns 503 when ADMIN_KEY is unset (removes the
 *     "is admin configured?" timing oracle).
 *   - Body shape validated BEFORE authAndCharge. No charge on malformed.
 *   - Scaffolder uses hoisted projectName (no ReferenceError on dup dir).
 */

export interface Env {
  LEADERBOARD: DurableObjectNamespace;
  ADMIN_KEY: string;
}

// ---- Types -----------------------------------------------------------------

type CallType = "example" | "read";
type Scope = "example" | "read" | "all";

const SCOPE_FOR: Record<CallType, Scope> = {
  example: "example",
  read: "read",
};

// Pricing in mcents (1 mcent = 1/1000¢ = $0.00001).
export const PRICE_MCENTS = {
  example: 100, // $0.001 per call — customize per handler
} as const;

export const XP_AWARD: Record<CallType, number> = {
  example: 10,
  read: 0,
};

// Admin mint ceiling. Prevents a compromised admin key from minting
// effectively-infinite balances before revocation. Tune per product.
const MAX_MINT_MCENTS = 100_000_000; // $1,000
const MAX_BODY_BYTES = 16 * 1024;
const KEY_PREFIX = "mcp_"; // service-namespaced so log scrapers tell mcpay keys apart

type KeyRecord = {
  balance_mcents: number;
  xp: number;
  created_at: number;
  last_active_at: number;
  display_name?: string;
  calls_total: number;
  calls_by_type: Partial<Record<CallType, number>>;
  badges: string[];
  // Required: no default-allow. Mint callers MUST pass an explicit array.
  scopes: Scope[];
};

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

// ---- Charging via Durable Object (atomic) ---------------------------------
//
// All mutations of a KeyRecord go through the DO. blockConcurrencyWhile()
// serializes concurrent requests against the same DO instance, giving us an
// atomic read-modify-write window. One DO instance per deployment — fine for
// templates; shard if you hit DO throughput limits.

type ChargeRequest = {
  op: "charge";
  key_hash: string;
  cost_mcents: number;
  call_type: CallType;
};
type MintRequest = {
  op: "mint";
  key_hash: string;
  rec: KeyRecord;
};
type ReadRequest = { op: "read"; key_hash: string };

export class LeaderboardDO {
  state: DurableObjectState;
  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const msg = (await req.json()) as ChargeRequest | MintRequest | ReadRequest;

    return this.state.blockConcurrencyWhile(async () => {
      if (msg.op === "mint") {
        await this.state.storage.put(`k:${msg.key_hash}`, msg.rec);
        return Response.json({ ok: true });
      }
      if (msg.op === "read") {
        const rec = (await this.state.storage.get<KeyRecord>(`k:${msg.key_hash}`)) || null;
        return Response.json({ ok: true, record: rec });
      }
      if (msg.op === "charge") {
        const rec = await this.state.storage.get<KeyRecord>(`k:${msg.key_hash}`);
        if (!rec) return Response.json({ ok: false, status: 401, error: "invalid api key" });
        if (!hasScope(rec, SCOPE_FOR[msg.call_type])) {
          return Response.json({
            ok: false, status: 403,
            error: `not authorized for scope "${SCOPE_FOR[msg.call_type]}"`,
            scopes: rec.scopes,
          });
        }
        if (rec.balance_mcents < msg.cost_mcents) {
          return Response.json({
            ok: false, status: 402,
            error: "insufficient balance",
            balance_mcents: rec.balance_mcents,
            required_mcents: msg.cost_mcents,
          });
        }
        const updated: KeyRecord = {
          ...rec,
          balance_mcents: rec.balance_mcents - msg.cost_mcents,
          xp: rec.xp + (XP_AWARD[msg.call_type] || 0),
          last_active_at: Date.now(),
          calls_total: rec.calls_total + 1,
          calls_by_type: {
            ...rec.calls_by_type,
            [msg.call_type]: (rec.calls_by_type[msg.call_type] || 0) + 1,
          },
        };
        await this.state.storage.put(`k:${msg.key_hash}`, updated);
        return Response.json({ ok: true, record: updated });
      }
      return Response.json({ ok: false, error: "unknown op" }, { status: 400 });
    });
  }
}

function doStub(env: Env): DurableObjectStub {
  return env.LEADERBOARD.get(env.LEADERBOARD.idFromName("global"));
}

async function authAndCharge(
  req: Request,
  env: Env,
  cost_mcents: number,
  call_type: CallType,
): Promise<{ ok: true; record: KeyRecord; key_hash: string } | Response> {
  const key = extractBearer(req);
  if (!key?.startsWith(KEY_PREFIX)) return error(401, "missing or malformed bearer token");

  const key_hash = await sha256Hex(key);
  const resp = await doStub(env).fetch(new Request("https://do/charge", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ op: "charge", key_hash, cost_mcents, call_type } as ChargeRequest),
  }));
  const r: any = await resp.json();
  if (!r.ok) return error(r.status || 400, r.error, { balance_mcents: r.balance_mcents, required_mcents: r.required_mcents, scopes: r.scopes });
  return { ok: true, record: r.record, key_hash };
}

// ---- Admin: mint new keys --------------------------------------------------

async function handleAdminMint(req: Request, env: Env): Promise<Response> {
  // 503 when unset — don't leak "is admin configured" via timing comparison.
  if (!env.ADMIN_KEY) return error(503, "admin not configured", {}, false);
  const provided = req.headers.get("X-Admin-Key") || "";
  if (!timingSafeEqual(provided, env.ADMIN_KEY)) {
    return error(401, "invalid admin key", {}, false);
  }

  // Bounded body read to avoid a memory DoS from a 1 GB POST.
  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) return error(413, "body too large", {}, false);
  let body: any;
  try { body = JSON.parse(raw); } catch { body = {}; }

  const n = Number(body.balance_mcents);
  if (!Number.isFinite(n) || n < 0) return error(400, "balance_mcents must be a finite non-negative number", {}, false);
  const balance_mcents = Math.min(MAX_MINT_MCENTS, Math.floor(n));

  const validScopes: Scope[] = ["example", "read", "all"];
  const scopes: Scope[] = Array.isArray(body.scopes)
    ? body.scopes.filter((s: any): s is Scope => validScopes.includes(s))
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
    body: JSON.stringify({ op: "mint", key_hash, rec } as MintRequest),
  }));
  if (!resp.ok) return error(500, "mint failed", {}, false);

  // Omit CORS on admin response — no browser should be making admin calls.
  return json({ ok: true, key, balance_mcents, scopes, max_mint_mcents: MAX_MINT_MCENTS }, { status: 200 }, false);
}

// ---- Example handler (replace with your own) ------------------------------

/**
 * Pattern: validate body FIRST (no charge on bad shape), THEN authAndCharge.
 * Copy this sequence into your real handlers or users burn mcents on typos.
 */
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

  const auth = await authAndCharge(req, env, PRICE_MCENTS.example, "example");
  if (auth instanceof Response) return auth;

  return json({
    ok: true,
    echoed: body.message.slice(0, 200),
    balance_mcents: auth.record.balance_mcents,
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
      // No CORS on admin preflight either — admin is non-browser.
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
    if (p === "/v1/example" && req.method === "POST") return handleExample(req, env);
    if (p === "/v1/admin/mint" && req.method === "POST") return handleAdminMint(req, env);

    return error(404, "not found");
  },
};
