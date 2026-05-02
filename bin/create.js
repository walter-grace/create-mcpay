#!/usr/bin/env node
/**
 * create-mcpay <name>
 *
 * Scaffolds a new Cloudflare Worker project with the mcpay agent gateway template.
 */
const fs = require("fs");
const path = require("path");

const name = process.argv[2];
if (!name) {
  console.error("usage: create-mcpay <project-name>");
  process.exit(1);
}

const target = path.resolve(process.cwd(), name);
// Use the directory's basename as the Worker/package identifier even if the
// user passed a longer path like "./projects/my-api". Hoisted above the
// existsSync check so the error message uses the resolved name.
const projectName = path.basename(target);
if (fs.existsSync(target)) {
  console.error(`error: directory "${projectName}" already exists`);
  process.exit(1);
}

fs.mkdirSync(target, { recursive: true });
fs.mkdirSync(path.join(target, "src"), { recursive: true });

const templateSrc = fs.readFileSync(path.join(__dirname, "..", "src", "template.ts"), "utf8");
fs.writeFileSync(path.join(target, "src", "index.ts"), templateSrc);

fs.writeFileSync(path.join(target, "wrangler.toml"), `name = "${projectName}"
main = "src/index.ts"
compatibility_date = "${new Date().toISOString().slice(0, 10)}"
compatibility_flags = ["nodejs_compat"]

# BillingDO holds all auth, balances, and charging atomically.
# Bearer tokens are stored as SHA-256 hashes — raw tokens never touch storage.

[[durable_objects.bindings]]
name = "BILLING"
class_name = "BillingDO"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["BillingDO"]

# ---- Required secrets (wrangler secret put <NAME>) -------------------------
# ADMIN_KEY        random 32-hex string; gates /v1/admin/mint

# ---- Optional: MPP signup — enables /v1/signup for autonomous key minting --
# Agents pay via Tempo (stablecoin), Stripe (card), or both. Set at least one
# payment method's secrets to activate the endpoint.
#
# Tempo (stablecoin, sub-second settlement on Tempo network):
#   TEMPO_RECIPIENT   your wallet address to receive USDC
#   TEMPO_CURRENCY    USDC token address on the Tempo network
#
# Stripe (card/wallet — Machine Payments must be enabled on your account):
#   STRIPE_RECIPIENT   your Stripe Business Network recipient ID
#   STRIPE_NETWORK_ID  your Stripe Business Network ID
#   STRIPE_SECRET_KEY  your Stripe secret key (sk_live_... or sk_test_...)
#
# Shared:
#   MPP_SECRET_KEY              HMAC secret for challenge integrity (recommended)
#   SIGNUP_PRICE_CENTS          price in USD cents, default 10 ($0.10)
#   DEFAULT_SIGNUP_BALANCE_MCENTS  mcents to mint per signup, default 10000 (100 calls)
#   DEFAULT_SIGNUP_SCOPES       comma-separated scopes, default "example"
`);

fs.writeFileSync(path.join(target, "package.json"), JSON.stringify({
  name: projectName,
  version: "0.1.0",
  private: true,
  scripts: {
    deploy: "wrangler deploy",
    dev: "wrangler dev",
    tail: "wrangler tail",
  },
  dependencies: {
    mppx: "^0.5.0",
  },
  devDependencies: {
    "@cloudflare/workers-types": "^4.20240909.0",
    typescript: "^5.5.4",
    wrangler: "^4.0.0",
  },
}, null, 2));

fs.writeFileSync(path.join(target, "tsconfig.json"), JSON.stringify({
  compilerOptions: {
    target: "ES2022",
    module: "ES2022",
    moduleResolution: "bundler",
    strict: true,
    esModuleInterop: true,
    skipLibCheck: true,
    types: ["@cloudflare/workers-types"],
  },
  include: ["src/**/*.ts"],
}, null, 2));

fs.writeFileSync(path.join(target, "README.md"), `# ${projectName}

A pay-per-call agent gateway built on Cloudflare Workers.

Scaffolded with [create-mcpay](https://npm.im/create-mcpay).

## Setup

\`\`\`bash
npm install
wrangler secret put ADMIN_KEY       # random 32-hex; gates /v1/admin/mint
wrangler deploy
\`\`\`

## Enable MPP signup (optional)

Lets agents self-serve API keys by paying with Tempo (stablecoin), Stripe (card), or both.
Set at least one payment method's secrets and \`/v1/signup\` activates automatically.

\`\`\`bash
# Tempo stablecoin
wrangler secret put TEMPO_RECIPIENT   # your wallet address
wrangler secret put TEMPO_CURRENCY    # USDC token address on Tempo network
wrangler secret put MPP_SECRET_KEY    # openssl rand -hex 32

# Stripe card (also requires Machine Payments enabled on your Stripe account)
wrangler secret put STRIPE_RECIPIENT
wrangler secret put STRIPE_NETWORK_ID
wrangler secret put STRIPE_SECRET_KEY

# Optional tuning
wrangler secret put SIGNUP_PRICE_CENTS             # default: 10 ($0.10)
wrangler secret put DEFAULT_SIGNUP_BALANCE_MCENTS  # default: 10000 (100 calls)
wrangler secret put DEFAULT_SIGNUP_SCOPES          # default: example
\`\`\`

## Next steps

- Replace \`handleExample\` in \`src/index.ts\` with your actual paid tools
- Ship a \`/llms.txt\` and \`/.well-known/mcp.json\` for Agent Readiness
- See [mpp.dev](https://mpp.dev) for the full MPP protocol docs
`);

console.log(`✓ Scaffolded ${projectName}/`);
console.log(`  cd ${projectName} && npm install && wrangler deploy`);
