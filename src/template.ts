/**
 * mcpay template — single-file Cloudflare Worker for pay-per-call agent APIs.
 *
 * Reusable primitives: bearer-token auth, mcent pricing, scoped keys,
 * XP leaderboard, admin-gated key minting. Replace the `/v1/example`
 * handler with your own paid tools.
 *
 * See the companion README.md for setup + deploy.
 *
 * Security posture of this template:
 *   - hasScope() is DEFAULT-DENY: undefined/empty scopes grant nothing.
 *     Callers must mint keys with an explicit scopes list.
 *   - Admin mint uses timingSafeEqual + crypto.getRandomValues.
 *   - handleExample validates the body BEFORE debiting — copy this pattern.
 *   - KV is eventually-consistent; concurrent charges on the same key can
 *     race to overdraft. For production, move balance into a Durable Object
 *     and wrap mutations in state.blockConcurrencyWhile(). The DO stub
 *     below is where you'd add that.
 */

export interface Env {
  KEYS: KVNamespace;
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

type KeyRecord = {
  balance_mcents: number;
  xp: number;
  created_at: number;
  last_active_at: number;
  display_name?: string;
  calls_total: number;
  calls_by_type: Partial<Record<CallType, number>>;
  badges: string[];
  // Scopes are required — no default-allow. Mint with e.g. ["example", "read"]
  // or ["all"] to grant everything.
  scopes: Scope[];
};

// ---- Primitives: auth + scope + charge ------------------------------------

/**
 * DEFAULT-DENY. If `scopes` is missing or empty, returns false — the key
 * has no permission. Callers must mint keys with an explicit scopes list.
 * Whitehat-audited: the previous default-allow-on-undefined pattern is a
 * classic privilege-escalation footgun.
 */
function hasScope(rec: KeyRecord, needed: Scope): boolean {
  const s = rec.scopes;
  if (!Array.isArray(s) || s.length === 0) return false;
  if (s.includes("all")) return true;
  return s.includes(needed);
}

async function readKey(env: Env, key: string): Promise<KeyRecord | null> {
  const raw = await env.KEYS.get(key);
  return raw ? JSON.parse(raw) as KeyRecord : null;
}

async function writeKey(env: Env, key: string, rec: KeyRecord) {
  await env.KEYS.put(key, JSON.stringify(rec));
}

function extractBearer(req: Request): string | null {
  const h = req.headers.get("Authorization");
  const m = h?.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function level(xp: number): number {
  return Math.floor(Math.sqrt(xp / 50));
}

function json(body: any, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      ...(init.headers || {}),
    },
  });
}

function error(status: number, message: string, extra?: any): Response {
  return json({ ok: false, error: message, ...(extra || {}) }, { status });
}

/**
 * Timing-safe comparison of two equal-length strings. Short-circuits on
 * length mismatch (safe — attacker can already measure length via Content-
 * Length / response timing on a mismatch). Main defense: constant-time scan
 * of the matching bytes.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function generateApiKey(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `k_${hex}`;
}

/**
 * Auth + debit + XP award. Split from validation: ALWAYS validate your
 * request body BEFORE calling this function, or a malformed request will
 * burn mcents. See handleExample for the canonical pattern.
 *
 * Known caveat: KV reads+writes here are NOT atomic. Under concurrent burst
 * traffic to the same key, multiple requests can pass the balance check and
 * debit from the same baseline (TOCTOU overdraft). For production, move this
 * to a Durable Object with blockConcurrencyWhile(). The template leaves it
 * on KV to keep the scaffold readable.
 */
async function authAndCharge(
  req: Request,
  env: Env,
  cost_mcents: number,
  call_type: CallType,
): Promise<{ ok: true; record: KeyRecord; key: string } | Response> {
  const key = extractBearer(req);
  if (!key?.startsWith("k_")) return error(401, "missing or malformed bearer token");
  const rec = await readKey(env, key);
  if (!rec) return error(401, "invalid api key");

  const needed = SCOPE_FOR[call_type];
  if (!hasScope(rec, needed)) {
    return error(403, `not authorized for scope "${needed}"`, { scopes: rec.scopes });
  }

  if (rec.balance_mcents < cost_mcents) {
    return error(402, "insufficient balance", {
      balance_mcents: rec.balance_mcents,
      required_mcents: cost_mcents,
    });
  }

  const updated: KeyRecord = {
    ...rec,
    balance_mcents: rec.balance_mcents - cost_mcents,
    xp: rec.xp + (XP_AWARD[call_type] || 0),
    last_active_at: Date.now(),
    calls_total: rec.calls_total + 1,
    calls_by_type: {
      ...rec.calls_by_type,
      [call_type]: (rec.calls_by_type[call_type] || 0) + 1,
    },
  };
  await writeKey(env, key, updated);
  return { ok: true, record: updated, key };
}

// ---- Admin: mint new keys -------------------------------------------------

/**
 * POST /v1/admin/mint
 * Headers: X-Admin-Key: <env.ADMIN_KEY>
 * Body:    { "balance_mcents": 100, "scopes": ["example"], "display_name"?: "..." }
 *
 * Returns the generated key ONCE. Store it client-side immediately — the
 * server never returns it again. Opinionated: scopes is REQUIRED.
 */
async function handleAdminMint(req: Request, env: Env): Promise<Response> {
  const provided = req.headers.get("X-Admin-Key") || "";
  if (!env.ADMIN_KEY || !timingSafeEqual(provided, env.ADMIN_KEY)) {
    return error(401, "invalid admin key");
  }

  const body: any = await req.json().catch(() => ({}));
  const balance_mcents = Math.max(0, Number(body.balance_mcents) || 0);
  const validScopes: Scope[] = ["example", "read", "all"];
  const scopes: Scope[] = Array.isArray(body.scopes)
    ? body.scopes.filter((s: any): s is Scope => validScopes.includes(s))
    : [];

  if (scopes.length === 0) {
    return error(400, 'scopes required: array of ["example","read","all"]', {
      note: "default-deny: a key with no scopes cannot call any paid endpoint",
    });
  }

  const key = generateApiKey();
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
  await writeKey(env, key, rec);
  return json({ ok: true, key, balance_mcents, scopes });
}

// ---- Example handler (replace with your own) ------------------------------

/**
 * Pattern: validate body FIRST (no charge on bad shape), THEN authAndCharge.
 * Copy this sequence into your real handlers or users will burn mcents on
 * typos before any work runs.
 */
async function handleExample(req: Request, env: Env): Promise<Response> {
  // 1. Validate body first — malformed requests don't get charged.
  const body: any = await req.json().catch(() => null);
  if (!body || typeof body.message !== "string" || body.message.length === 0) {
    return error(400, 'missing required field "message" (non-empty string)', {
      expected: { message: "<your input>" },
      note: "no charge applied",
    });
  }

  // 2. Auth + charge. Only runs if validation passed.
  const auth = await authAndCharge(req, env, PRICE_MCENTS.example, "example");
  if (auth instanceof Response) return auth;

  // 3. Do the work. If this throws, the mcents are already debited —
  //    implement refund logic (see the DLF reference implementation) if your
  //    handler can fail on transient issues.
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
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          // Intentionally omit X-Admin-Key — don't advertise admin headers
          // via preflight. Admin tooling uses non-browser clients anyway.
          "Access-Control-Allow-Headers": "Authorization, Content-Type",
        },
      });
    }

    if (p === "/v1/health") return json({ ok: true, ts: Date.now() });
    if (p === "/v1/pricing") return json({ prices_mcents: PRICE_MCENTS });
    if (p === "/v1/example" && req.method === "POST") return handleExample(req, env);
    if (p === "/v1/admin/mint" && req.method === "POST") return handleAdminMint(req, env);

    // Flat 404 — don't echo method+path (minor recon hardening).
    return error(404, "not found");
  },
};

// ---- Durable Object stub ---------------------------------------------------
// For production, move balance + charging into this DO so concurrent mutations
// on the same key are serialized via state.blockConcurrencyWhile(). The KV
// path above has a TOCTOU window on bursts to the same key.
export class LeaderboardDO {
  state: DurableObjectState;
  constructor(state: DurableObjectState) { this.state = state; }
  async fetch(_req: Request): Promise<Response> {
    return new Response("stub — move balance + leaderboard here for atomic updates");
  }
}
