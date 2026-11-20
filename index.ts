/**
 * Odoo MCP OAuth Server
 *
 * A multi-user OAuth proxy MCP server that connects Dust (or any MCP client)
 * to Odoo via a native "Connect" button. Each user authenticates independently
 * with their own Odoo credentials (URL + DB + username + password).
 *
 * Architecture:
 *   Dust ←→ [This server (OAuth proxy + MCP)] ←→ Odoo Web Session API
 *
 * OAuth flow implemented:
 *   RFC 9728: Protected Resource Metadata
 *   RFC 8414: Authorization Server Metadata
 *   RFC 7591: Dynamic Client Registration
 *   RFC 7636: PKCE (S256 only)
 *   The /authorize endpoint serves an HTML form to capture Odoo credentials,
 *   since Odoo has no standard OAuth2 authorization server.
 *
 * Odoo authentication:
 *   Uses /web/session/authenticate to exchange login+password for a session
 *   cookie once. The password is never stored — only the session cookie is
 *   retained and replayed on subsequent /web/dataset/call_kw calls.
 */

import express, { type Request, type Response } from 'express';
import cors from 'cors';
import axios from 'axios';
import rateLimit from 'express-rate-limit';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.set('trust proxy', 1); // Required for correct IP detection behind Railway / any reverse proxy
const PORT = parseInt(process.env.PORT ?? '3000');

// Optional pre-shared secret for the /register endpoint (RFC 7591 §3.4).
// Set CLIENT_REGISTRATION_SECRET in .env to require it; leave empty to allow
// unauthenticated registration (only safe in trusted private deployments).
const CLIENT_REGISTRATION_SECRET = process.env.CLIENT_REGISTRATION_SECRET ?? '';

// AUTO-DETECT BASE_URL
function resolveBaseUrl(): string {
  let base =
    process.env.BASE_URL ??
    (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : null) ??
    `http://localhost:${PORT}`;

  base = base.replace(/\/$/, '');

  if (!base.startsWith('http://') && !base.startsWith('https://')) {
    base = `https://${base}`;
  }

  return base;
}
const BASE_URL = resolveBaseUrl();

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowedHeaders: ['*'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
// TYPES
// ============================================================

interface OdooContext {
  url: string;
  db: string;
  sessionId: string; // Odoo web session cookie — password is never stored here
}

interface PendingAuth {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  createdAt: number;
}

interface AuthCode {
  clientId: string;
  odooCtx: OdooContext;
  codeChallenge: string;
  codeChallengeMethod: string;
  redirectUri: string;
  createdAt: number;
}

interface StoredToken {
  ctx: OdooContext;
  createdAt: number;
}

// ============================================================
// IN-MEMORY STORES
// ============================================================

const registeredClients = new Map<string, { clientSecret: string; redirectUris: string[] }>();
const pendingAuths = new Map<string, PendingAuth>();   // keyed by state
const authCodes = new Map<string, AuthCode>();         // keyed by code
const accessTokens = new Map<string, StoredToken>();   // keyed by bearer token

// ============================================================
// TOKEN PERSISTENCE (Railway Volume at /data)
// ============================================================
// accessTokens and registeredClients survive restarts via the Railway Volume.
// pendingAuths and authCodes are short-lived (≤15 min TTL) and not persisted.

const DATA_DIR = process.env.DATA_DIR ?? '/data';
const TOKENS_FILE  = `${DATA_DIR}/tokens.json`;
const CLIENTS_FILE = `${DATA_DIR}/clients.json`;

function loadTokens(): void {
  try {
    if (!existsSync(TOKENS_FILE)) return;
    const raw = readFileSync(TOKENS_FILE, 'utf8');
    const entries = JSON.parse(raw) as Array<[string, StoredToken]>;
    const cutoff = Date.now() - 365 * 24 * 60 * 60_000;
    let loaded = 0;
    for (const [token, stored] of entries) {
      if (stored.createdAt > cutoff) {
        accessTokens.set(token, stored);
        loaded++;
      }
    }
    if (loaded > 0) console.log(`Restored ${loaded} session(s) from disk.`);
  } catch (err) {
    console.warn('Could not load tokens from disk (starting fresh):', err);
  }
}

function saveTokens(): void {
  try {
    mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(TOKENS_FILE, JSON.stringify([...accessTokens.entries()]), 'utf8');
  } catch (err) {
    console.warn('Could not save tokens to disk:', err);
  }
}

function loadClients(): void {
  try {
    if (!existsSync(CLIENTS_FILE)) return;
    const raw = readFileSync(CLIENTS_FILE, 'utf8');
    const entries = JSON.parse(raw) as Array<[string, { clientSecret: string; redirectUris: string[] }]>;
    for (const [id, data] of entries) registeredClients.set(id, data);
    if (entries.length > 0) console.log(`Restored ${entries.length} registered client(s) from disk.`);
  } catch (err) {
    console.warn('Could not load registered clients from disk (starting fresh):', err);
  }
}

function saveClients(): void {
  try {
    mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(CLIENTS_FILE, JSON.stringify([...registeredClients.entries()]), 'utf8');
  } catch (err) {
    console.warn('Could not save registered clients to disk:', err);
  }
}

// Restore sessions immediately on startup
loadTokens();
loadClients();

// Periodic save every 5 minutes — guards against hard crashes (SIGKILL, OOM)
setInterval(() => { saveTokens(); saveClients(); }, 5 * 60_000);

// Graceful shutdown: Railway sends SIGTERM before stopping the container
process.on('SIGTERM', () => { saveTokens(); saveClients(); process.exit(0); });
process.on('SIGINT',  () => { saveTokens(); saveClients(); process.exit(0); });

// Auth codes: 10-minute TTL. Interval runs every 2 min so the window is strict.
setInterval(() => {
  const cutoff = Date.now() - 10 * 60_000;
  for (const [k, v] of authCodes) {
    if (v.createdAt < cutoff) authCodes.delete(k);
  }
}, 2 * 60_000);

// Pending auths: 15-minute TTL for abandoned flows.
setInterval(() => {
  const cutoff = Date.now() - 15 * 60_000;
  for (const [k, v] of pendingAuths) {
    if (v.createdAt < cutoff) pendingAuths.delete(k);
  }
}, 5 * 60_000);

// Access tokens: 1-year backstop cleanup (memory leak guard only).
// Active sessions are kept alive by the keepalive interval below.
setInterval(() => {
  const cutoff = Date.now() - 365 * 24 * 60 * 60_000;
  for (const [k, v] of accessTokens) {
    if (v.createdAt < cutoff) accessTokens.delete(k);
  }
}, 24 * 60 * 60_000);

// Keepalive: prevent Odoo sessions from expiring due to inactivity.
// Runs every 6 days — below Odoo's default 1-week session timeout.
// Only removes the token on confirmed session expiry — transient network
// errors are ignored so a momentary Odoo blip can't silently kill a session.
setInterval(async () => {
  for (const [token, stored] of accessTokens) {
    try {
      const client = new OdooClient(stored.ctx);
      await client.callKw('res.lang', 'search_count', [[]], {});
    } catch (err) {
      if (err instanceof OdooSessionExpiredError) {
        accessTokens.delete(token);
      }
    }
  }
}, 6 * 24 * 60 * 60_000);

// ============================================================
// SSRF PROTECTION
// ============================================================

function isPrivateUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return true;
    const h = u.hostname.toLowerCase();

    // Loopback / reserved hostnames
    if (h === 'localhost') return true;
    if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.localhost')) return true;

    // IPv6 — block all literals; legitimate Odoo servers use domain names
    if (h.includes(':')) return true;

    // IPv4 private ranges
    const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4) {
      const [a, b] = ipv4.slice(1).map(Number);
      if (a === 10) return true;                          // 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
      if (a === 192 && b === 168) return true;            // 192.168.0.0/16
      if (a === 127) return true;                         // 127.0.0.0/8
      if (a === 169 && b === 254) return true;            // 169.254.0.0/16 (AWS metadata / link-local)
      if (a === 0) return true;
    }

    return false;
  } catch {
    return true; // unparseable URL → block
  }
}

// ============================================================
// CONSTANT-TIME STRING COMPARISON
// ============================================================

function safeCompare(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  // Buffers must be same length for timingSafeEqual; pad shorter one to avoid length leak
  if (aBuf.length !== bBuf.length) {
    timingSafeEqual(aBuf, Buffer.alloc(aBuf.length)); // dummy compare to normalize timing
    return false;
  }
  return timingSafeEqual(aBuf, bBuf);
}

// ============================================================
// PKCE VERIFICATION (RFC 7636) — S256 only; plain is rejected
// ============================================================

function verifyPKCE(verifier: string, challenge: string, method: string): boolean {
  if (method !== 'S256') return false;
  const hash = createHash('sha256').update(verifier).digest('base64url');
  return hash === challenge;
}

// ============================================================
// CUSTOM ERRORS
// ============================================================

class OdooSessionExpiredError extends Error {
  constructor() {
    super('Odoo session expired — please reconnect from Dust.');
    this.name = 'OdooSessionExpiredError';
  }
}

// ============================================================
// ODOO WEB SESSION CLIENT
//
// Uses /web/session/authenticate to get a session cookie once,
// then /web/dataset/call_kw with that cookie for all subsequent calls.
// The login password is never stored — only the session cookie is retained.
// ============================================================

let rpcCounter = 0;
function nextId(): number { return ++rpcCounter; }

class OdooClient {
  readonly db: string;
  readonly url: string;
  /** Opaque per-session key (field visibility depends on the user's groups). */
  readonly cacheKey: string;
  private readonly baseUrl: string;
  private readonly cookieHeader: string;

  constructor(private readonly ctx: OdooContext) {
    this.baseUrl = ctx.url.replace(/\/$/, '');
    this.db = ctx.db;
    this.url = ctx.url;
    this.cookieHeader = `session_id=${ctx.sessionId}`;
    this.cacheKey = createHash('sha256').update(`${ctx.url}|${ctx.db}|${ctx.sessionId}`).digest('hex');
  }

  async callKw(
    model: string,
    method: string,
    args: unknown[],
    kwargs: Record<string, unknown> = {},
  ): Promise<unknown> {
    const resp = await axios.post(
      `${this.baseUrl}/web/dataset/call_kw`,
      {
        jsonrpc: '2.0', method: 'call', id: nextId(),
        params: { model, method, args, kwargs: { context: {}, ...kwargs } },
      },
      { headers: { 'Content-Type': 'application/json', Cookie: this.cookieHeader }, timeout: 30_000, maxRedirects: 0 },
    );
    if (resp.data.error) {
      const msg: string = resp.data.error.data?.message ?? resp.data.error.message ?? 'Odoo error';
      // Detect session expiry by error code (100 = Odoo session invalid) or known
      // exact phrases — intentionally narrow to avoid false positives on business
      // errors that happen to mention the word "session".
      const lmsg = msg.toLowerCase();
      const isSessionError =
        resp.data.error.code === 100 ||
        lmsg.includes('session invalid') ||
        lmsg.includes('session expired') ||
        lmsg === 'odoo session invalid';
      if (isSessionError) throw new OdooSessionExpiredError();
      throw new Error(msg);
    }
    return resp.data.result;
  }

  async serverVersion(): Promise<Record<string, unknown>> {
    const resp = await axios.post(
      `${this.baseUrl}/jsonrpc`,
      { jsonrpc: '2.0', method: 'call', id: nextId(), params: { service: 'common', method: 'version', args: [] } },
      { headers: { 'Content-Type': 'application/json' }, timeout: 10_000, maxRedirects: 0 },
    );
    if (resp.data.error) throw new Error(resp.data.error.message ?? 'Version check failed');
    return resp.data.result as Record<string, unknown>;
  }
}

// ============================================================
// ODOO AUTHENTICATION HELPERS
// ============================================================

/**
 * Authenticate with Odoo's web session API and return the session cookie.
 * The password is used here and immediately discarded — it is never stored.
 */
async function odooAuthenticate(url: string, db: string, username: string, password: string): Promise<string> {
  const baseUrl = url.replace(/\/$/, '');
  const resp = await axios.post(
    `${baseUrl}/web/session/authenticate`,
    {
      jsonrpc: '2.0', method: 'call', id: nextId(),
      params: { db, login: username, password },
    },
    { headers: { 'Content-Type': 'application/json' }, timeout: 10_000, maxRedirects: 0 },
  );

  if (resp.data.error) {
    const msg: string = resp.data.error.data?.message ?? 'Authentication failed';
    throw new Error(msg);
  }

  const uid: number = resp.data.result?.uid as number;
  if (!uid) throw new Error('Invalid credentials — check your username and password.');

  // Extract session_id from Set-Cookie response header
  const setCookie = resp.headers['set-cookie'];
  const cookies = Array.isArray(setCookie) ? setCookie : [setCookie ?? ''];
  for (const c of cookies) {
    const m = c?.match(/session_id=([^;]+)/);
    if (m) return m[1];
  }

  throw new Error('Odoo did not return a session cookie. Check that the server URL is correct.');
}

/** Try to auto-detect the database name (works when only 1 DB exists). */
async function detectDb(url: string): Promise<string | null> {
  try {
    const resp = await axios.post(
      `${url.replace(/\/$/, '')}/web/database/list`,
      { jsonrpc: '2.0', method: 'call', id: nextId(), params: {} },
      { headers: { 'Content-Type': 'application/json' }, timeout: 5_000, maxRedirects: 0 },
    );
    const dbs: string[] = resp.data.result as string[];
    if (Array.isArray(dbs) && dbs.length === 1) return dbs[0];
    return null;
  } catch {
    return null;
  }
}

// ============================================================
// RATE LIMITERS
// ============================================================

const registerLimiter = rateLimit({ windowMs: 60 * 60_000, max: 30,  standardHeaders: true, legacyHeaders: false });
const authLimiter    = rateLimit({ windowMs: 15 * 60_000, max: 20,  standardHeaders: true, legacyHeaders: false });
const tokenLimiter   = rateLimit({ windowMs: 15 * 60_000, max: 60,  standardHeaders: true, legacyHeaders: false });
// Per-IP limit on MCP calls — prevents a compromised token from flooding Odoo
const mcpLimiter     = rateLimit({ windowMs: 15 * 60_000, max: 300, standardHeaders: true, legacyHeaders: false });

// ============================================================
// OAUTH ENDPOINTS
// ============================================================

// RFC 9728 — resource matches the /mcp endpoint so the client sees exactly
// one OAuth resource and does not create a duplicate MCP connection.
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json({
    resource: `${BASE_URL}/mcp`,
    authorization_servers: [BASE_URL],
    scopes_supported: ['odoo'],
    bearer_methods_supported: ['header'],
  });
});

/** RFC 8414 — OAuth 2.0 Authorization Server Metadata */
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    registration_endpoint: `${BASE_URL}/register`,
    scopes_supported: ['odoo'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'], // plain removed — insecure per RFC 9700
  });
});

/** RFC 7591 — Dynamic Client Registration */
app.post('/register', registerLimiter, (req, res) => {
  if (CLIENT_REGISTRATION_SECRET) {
    const auth = req.headers.authorization ?? '';
    if (!safeCompare(auth, `Bearer ${CLIENT_REGISTRATION_SECRET}`)) {
      return res.status(401).json({ error: 'unauthorized', error_description: 'Invalid registration secret' });
    }
  }

  const { redirect_uris = [], client_name } = req.body as { redirect_uris?: string[]; client_name?: string };
  const clientId = randomBytes(16).toString('hex');
  const clientSecret = randomBytes(32).toString('hex');
  registeredClients.set(clientId, { clientSecret, redirectUris: redirect_uris });
  saveClients();
  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name: client_name ?? 'Dust MCP Client',
    redirect_uris,
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_post',
  });
});

/** Authorization endpoint — serves an HTML credential form. */
app.get('/authorize', authLimiter, (req, res) => {
  const q = req.query as Record<string, string>;
  const { state, redirect_uri, client_id, code_challenge, code_challenge_method } = q;

  if (!state || !redirect_uri || !code_challenge) {
    return res.status(400).send('<h2>Missing required OAuth parameters (state, redirect_uri, code_challenge).</h2>');
  }

  const client = registeredClients.get(client_id ?? '');
  if (client && !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send('<h2>redirect_uri is not registered for this client.</h2>');
  }

  pendingAuths.set(state, {
    clientId: client_id ?? '',
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method ?? 'S256',
    createdAt: Date.now(),
  });

  res.set('X-Frame-Options', 'DENY')
     .set('X-Content-Type-Options', 'nosniff')
     .set('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'`)
     .send(renderConnectForm(state));
});

/** Handle the credential form submission */
app.post('/authorize/submit', authLimiter, async (req, res) => {
  const { state, odoo_url, odoo_db, odoo_user, odoo_password } = req.body as Record<string, string>;

  const pending = pendingAuths.get(state);
  if (!pending) {
    return res.status(400).send('<h2>Session expired or invalid. Please try connecting again from Dust.</h2>');
  }

  const url = (odoo_url ?? '').trim().replace(/\/$/, '').slice(0, 2048);
  let db = (odoo_db ?? '').trim().slice(0, 255);
  const username = (odoo_user ?? '').trim().slice(0, 255);
  const password = (odoo_password ?? '').trim().slice(0, 1024);

  // Re-render the form in-place with an error message — no redirect (Dust intercepts 302s)
  const sendForm = (err?: string) =>
    res.set('X-Frame-Options', 'DENY')
       .set('X-Content-Type-Options', 'nosniff')
       .set('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'`)
       .send(renderConnectForm(state, { url, db, username }, err));

  if (!url || !username || !password) {
    return sendForm('Odoo URL, email, and password are required.');
  }

  // SSRF protection — block private/internal URLs (don't reflect the URL back)
  if (isPrivateUrl(url)) {
    return sendForm('Invalid Odoo URL. Private or non-HTTP(S) URLs are not allowed.');
  }

  try {
    if (!db) {
      const detected = await detectDb(url);
      if (!detected) {
        return sendForm('Could not auto-detect the database name. Please enter it manually.');
      }
      db = detected;
    }

    // Authenticate — password is used once here and immediately discarded
    const sessionId = await odooAuthenticate(url, db, username, password);
    const odooCtx: OdooContext = { url, db, sessionId };

    const code = randomBytes(32).toString('hex');
    authCodes.set(code, {
      clientId: pending.clientId,
      odooCtx,
      codeChallenge: pending.codeChallenge,
      codeChallengeMethod: pending.codeChallengeMethod,
      redirectUri: pending.redirectUri,
      createdAt: Date.now(),
    });

    pendingAuths.delete(state);

    const redirectUrl = new URL(pending.redirectUri);
    redirectUrl.searchParams.set('code', code);
    redirectUrl.searchParams.set('state', state);
    res.redirect(redirectUrl.toString());

  } catch (err: unknown) {
    const msg = extractErrorMessage(err, 'Authentication failed. Please check your credentials.');
    sendForm(msg);
  }
});

/** Token endpoint — exchanges auth code for bearer token */
app.post('/token', tokenLimiter, (req, res) => {
  const { grant_type, code, code_verifier, client_id, client_secret } = req.body as Record<string, string>;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const authCode = authCodes.get(code);
  if (!authCode) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' });
  }

  // Validate client credentials when the client is registered
  const client = registeredClients.get(client_id ?? '');
  if (client) {
    if (client_id !== authCode.clientId || client.clientSecret !== client_secret) {
      authCodes.delete(code);
      return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client credentials' });
    }
  }

  // PKCE is mandatory — reject requests without code_verifier
  if (!code_verifier) {
    authCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier is required' });
  }
  if (!verifyPKCE(code_verifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
    authCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
  }

  const accessToken = randomBytes(32).toString('hex');
  accessTokens.set(accessToken, { ctx: authCode.odooCtx, createdAt: Date.now() });
  authCodes.delete(code);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 86_400 * 365, // 1 year — session kept alive by server-side keepalive
    scope: 'odoo',
  });
});

// ============================================================
// WRITE GUARDS — one tool = one ORM operation
//
// Each write tool must perform exactly one kind of operation, so that blocking
// a tool in the MCP client (e.g. Dust) cannot be bypassed through another one:
//   create_record → creates new records (and new sub-records) only
//   update_record → modifies the target record only
//   delete_record → deletes the target record only
//
// Without these checks, Odoo's generic ORM mechanisms let one tool do another
// tool's job:
//   - x2many commands: [0,_,vals] creates, [1,id,vals] writes on ANY record,
//     [2,id] deletes ANY record; on one2many fields, [3]/[5]/[6]/false delete
//     lines whose inverse is ondelete='cascade', and [4]/[6] re-parent
//     existing lines.
//   - related / delegated (_inherits) fields: setting them on create together
//     with a link to an existing record writes on that existing record
//     (e.g. product.product + product_tmpl_id=<existing> + list_price).
//   - technical models: creating ir.cron / ir.actions.server / base.automation
//     schedules arbitrary code; editing res.users / res.groups / ir.rule /
//     ir.model.access changes access rights.
//
// Odoo access rights remain the real security boundary: these guards cover the
// generic ORM mechanisms, not custom business logic in create()/write()
// overrides, compute inverses or automated actions configured in Odoo.
// ============================================================

type WriteVerb = 'create' | 'update';

const PROTECTED_MODEL_PREFIXES = ['ir.'];
const PROTECTED_MODELS = ['base.automation', 'res.users', 'res.groups'];

function isProtectedModel(model: string): boolean {
  return (
    PROTECTED_MODEL_PREFIXES.some(p => model.startsWith(p)) ||
    PROTECTED_MODELS.some(m => model === m || model.startsWith(`${m}.`))
  );
}

function assertWritableModel(model: string): void {
  if (isProtectedModel(model)) {
    throw new Error(`Model "${model}" is a technical model and cannot be modified via MCP.`);
  }
}

interface FieldMeta {
  type: string;
  relation?: string;
  related?: string | false;
}

const FIELDS_CACHE_TTL = 10 * 60_000;
const FIELDS_CACHE_MAX = 2_000;
const fieldsCache = new Map<string, { at: number; fields: Record<string, FieldMeta> }>();

async function getFieldsMeta(client: OdooClient, model: string): Promise<Record<string, FieldMeta>> {
  const key = `${client.cacheKey}|${model}`;
  const hit = fieldsCache.get(key);
  if (hit && Date.now() - hit.at < FIELDS_CACHE_TTL) return hit.fields;

  const fields = await client.callKw(model, 'fields_get', [], {
    attributes: ['type', 'relation', 'related'],
  }) as Record<string, FieldMeta>;

  if (fieldsCache.size >= FIELDS_CACHE_MAX) fieldsCache.clear();
  fieldsCache.set(key, { at: Date.now(), fields });
  return fields;
}

const MAX_SUBRECORD_DEPTH = 4;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const isRecordId = (v: unknown): boolean => Number.isInteger(v) && (v as number) > 0;

/**
 * Throws unless `values` only performs `verb` on `model`.
 * Nested sub-record values ([0, 0, {...}]) are checked recursively as creates.
 */
async function assertSafeValues(
  client: OdooClient,
  model: string,
  values: unknown,
  verb: WriteVerb,
  depth = 0,
): Promise<void> {
  assertWritableModel(model);
  if (!isPlainObject(values)) {
    throw new Error(`"values" for ${model} must be an object of field values.`);
  }
  if (depth > MAX_SUBRECORD_DEPTH) {
    throw new Error('Too many levels of nested sub-records.');
  }

  const meta = await getFieldsMeta(client, model);
  const relatedHops = new Set<string>();

  for (const [name, value] of Object.entries(values)) {
    const field = meta[name];
    const where = `${model}.${name}`;
    if (!field) throw new Error(`Unknown field "${where}".`);

    // Related and delegated fields write through to the record they point to.
    // On create, that record must be created by this very call, never an existing one.
    if (verb === 'create' && typeof field.related === 'string' && field.related) {
      const hop = field.related.split('.')[0];
      if (hop in values) {
        throw new Error(
          `"${where}" is a related field: setting it together with "${hop}" would modify ` +
          `an existing record. create_record only creates records; use update_record for that change.`,
        );
      }
      relatedHops.add(hop);
    }

    switch (field.type) {
      case 'many2one':
        if (value !== false && value !== null && !isRecordId(value)) {
          throw new Error(`"${where}" expects a record ID (integer) or false.`);
        }
        break;

      case 'one2many':
        await assertOne2manyValue(client, field, value, verb, where, depth);
        break;

      case 'many2many':
        await assertMany2manyValue(client, field, value, verb, where, depth);
        break;
    }
  }

  // Same protection when the link to the target record would come from a default value.
  if (relatedHops.size > 0) {
    const defaults = await client.callKw(model, 'default_get', [[...relatedHops]], {}) as Record<string, unknown>;
    const linked = [...relatedHops].filter(hop => defaults?.[hop]);
    if (linked.length > 0) {
      throw new Error(
        `Related fields of ${model} would write on the existing record(s) linked by default ` +
        `through ${linked.map(h => `"${h}"`).join(', ')}. create_record only creates records; use update_record for that change.`,
      );
    }
  }
}

async function assertOne2manyValue(
  client: OdooClient, field: FieldMeta, value: unknown, verb: WriteVerb, where: string, depth: number,
): Promise<void> {
  const lineModel = field.relation ?? 'the line model';

  if (verb === 'update') {
    // Any one2many command can create, modify, re-parent or (cascade-)delete lines.
    if (Array.isArray(value) && value.length === 0) return;
    throw new Error(
      `update_record cannot change the lines of "${where}". ` +
      `Use create_record, update_record or delete_record directly on ${lineModel}.`,
    );
  }

  // create: only brand-new lines are allowed ([0, 0, {...}]).
  if (value === false || value === null) return; // no-op on a new record
  if (!Array.isArray(value)) throw new Error(`"${where}" expects a list of commands.`);
  for (const cmd of value) {
    if (Array.isArray(cmd) && cmd[0] === 0 && isPlainObject(cmd[2])) {
      await assertSafeValues(client, lineModel, cmd[2], 'create', depth + 1);
      continue;
    }
    throw new Error(
      `create_record can only create new lines in "${where}" with [0, 0, {...}]. ` +
      `Use update_record or delete_record on ${lineModel} for existing lines.`,
    );
  }
}

async function assertMany2manyValue(
  client: OdooClient, field: FieldMeta, value: unknown, verb: WriteVerb, where: string, depth: number,
): Promise<void> {
  // false / null clears the relation only — the linked records are untouched.
  if (value === false || value === null) return;
  if (!Array.isArray(value)) throw new Error(`"${where}" expects a list of IDs or commands.`);
  if (value.length === 0) return;

  // Plain list of IDs = replace the relation (relation table only).
  if (!Array.isArray(value[0])) {
    if (value.every(isRecordId)) return;
    throw new Error(`"${where}" expects a list of record IDs or a list of commands.`);
  }

  for (const cmd of value) {
    if (!Array.isArray(cmd)) throw new Error(`"${where}" mixes IDs and commands.`);
    const [op, arg1, arg2] = cmd as [unknown, unknown, unknown];

    if (op === 0 && verb === 'create' && isPlainObject(arg2)) {
      await assertSafeValues(client, field.relation ?? '', arg2, 'create', depth + 1);
      continue;
    }
    // 3 = unlink, 4 = link, 5 = clear, 6 = replace: relation table only.
    if ((op === 3 || op === 4) && isRecordId(arg1)) continue;
    if (op === 5) continue;
    if (op === 6 && Array.isArray(arg2) && arg2.every(isRecordId)) continue;

    throw new Error(
      `Command [${String(op)}, ...] is not allowed in "${where}" with ${verb}_record: ` +
      `only linking / unlinking existing records ([3, id], [4, id], [5], [6, 0, ids])` +
      (verb === 'create' ? ' or creating new ones ([0, 0, {...}])' : '') +
      ` is permitted. Use the dedicated tool on ${field.relation ?? 'the related model'} instead.`,
    );
  }
}

// ============================================================
// BUSINESS ACTIONS — server-side allowlist
//
// run_business_action replaces the former execute_method tool, which could call
// any Odoo method and therefore bypass every other tool. It only runs the
// methods listed in the ALLOWED_METHODS environment variable, as comma-separated
// "model:method" pairs. The check runs on every call, before anything is sent
// to Odoo, whatever the agent asks:
//   - empty or unset variable → every call is refused;
//   - exact match only, no wildcard;
//   - generic ORM methods, private methods and technical models are never
//     accepted, even when listed;
//   - the call only carries record IDs: no free arguments, empty Odoo context.
// The variable is read at startup: redeploy after changing it.
// ============================================================

const NEVER_ALLOWED_METHODS = new Set([
  // Generic writes — handled (and guarded) by create_record / update_record / delete_record
  'create', 'write', 'unlink', 'copy', 'copy_data', 'load', 'web_save', 'name_create',
  'toggle_active', 'action_archive', 'action_unarchive',
  // Generic reads — handled by the read tools
  'read', 'search', 'search_read', 'search_count', 'search_fetch', 'read_group', 'web_read',
  'web_read_group', 'web_search_read', 'name_search', 'name_get', 'fields_get', 'default_get',
  'onchange', 'export_data', 'get_views', 'fields_view_get', 'get_metadata',
  // Environment switches
  'sudo', 'with_user', 'with_context', 'with_company', 'with_env',
]);

// model: lowercase segments separated by dots; method: must not start with "_" (private).
const ALLOWED_METHOD_ENTRY = /^([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*):([a-zA-Z][a-zA-Z0-9_]*)$/;

function parseAllowedMethods(raw: string | undefined): Set<string> {
  const allowed = new Set<string>();
  for (const entry of (raw ?? '').split(',').map(s => s.trim()).filter(Boolean)) {
    const match = ALLOWED_METHOD_ENTRY.exec(entry);
    if (!match) {
      console.warn(`ALLOWED_METHODS: ignoring "${entry}" (expected model:method).`);
      continue;
    }
    const [, model, method] = match;
    if (NEVER_ALLOWED_METHODS.has(method)) {
      console.warn(`ALLOWED_METHODS: ignoring "${entry}" (generic ORM method, use the dedicated tools).`);
      continue;
    }
    if (isProtectedModel(model)) {
      console.warn(`ALLOWED_METHODS: ignoring "${entry}" (technical model).`);
      continue;
    }
    allowed.add(`${model}:${method}`);
  }
  return allowed;
}

const ALLOWED_METHODS = parseAllowedMethods(process.env.ALLOWED_METHODS);
const MAX_ACTION_RECORDS = 100;

const ALLOWED_METHODS_SUMMARY = ALLOWED_METHODS.size === 0
  ? 'No business action is currently authorized on this server: every call is refused.'
  : `Authorized actions (model:method): ${[...ALLOWED_METHODS].join(', ')}. Any other action is refused.`;

// ============================================================
// MCP TOOL DEFINITIONS
// ============================================================

const MCP_TOOLS = [
  {
    name: 'search_records',
    description: 'Search for records in an Odoo model. Returns matching records with their fields.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: "Odoo model name (e.g. 'res.partner', 'sale.order', 'account.move')" },
        domain: {
          type: 'array',
          description: "Odoo domain filter. Examples: [['is_company','=',true]], [['state','in',['sale','done']]]. Use [] for all records.",
          default: [],
        },
        fields: {
          type: 'array',
          items: { type: 'string' },
          description: "Fields to return. Empty array returns all fields. Example: ['name','email','phone']",
          default: [],
        },
        limit: { type: 'number', description: 'Max records to return (default: 10, max: 1000)', default: 10 },
        offset: { type: 'number', description: 'Number of records to skip for pagination (default: 0)', default: 0 },
        order: { type: 'string', description: "Sort order. Example: 'name asc' or 'date_order desc'" },
        include_total: { type: 'boolean', description: 'Whether to fetch the total record count (requires an extra Odoo call). Default: false', default: false },
      },
      required: ['model'],
    },
  },
  {
    name: 'get_record',
    description: 'Get a specific Odoo record by its ID.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name' },
        id: { type: 'number', description: 'Record ID' },
        fields: {
          type: 'array',
          items: { type: 'string' },
          description: "Fields to return. Empty = all fields. Example: ['name','email','state']",
          default: [],
        },
      },
      required: ['model', 'id'],
    },
  },
  {
    name: 'create_record',
    description:
      'Create a new record in an Odoo model. Returns the ID of the created record. ' +
      'Only creates: it never modifies or deletes existing records. One2many lines can be created inline ' +
      'with [[0, 0, {...}]]; many2many fields accept a list of IDs to link. Technical models (ir.*, ' +
      'base.automation, res.users, res.groups) cannot be modified.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name' },
        values: {
          type: 'object',
          description:
            'Field values for the new record. Example: {"name": "ACME Corp", "is_company": true}. ' +
            'Sale order with lines: {"partner_id": 7, "order_line": [[0, 0, {"product_id": 3, "product_uom_qty": 2}]]}',
        },
      },
      required: ['model', 'values'],
    },
  },
  {
    name: 'update_record',
    description:
      'Update fields of one existing Odoo record. Only modifies that record: it cannot create or delete ' +
      'records. One2many lines cannot be changed here — use create_record, update_record or delete_record ' +
      'directly on the line model (e.g. sale.order.line). Many2many fields: [[4, id]] to link, [[3, id]] to ' +
      'unlink, [[6, 0, [ids]]] to replace. Technical models (ir.*, base.automation, res.users, res.groups) ' +
      'cannot be modified.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name' },
        id: { type: 'number', description: 'Record ID to update' },
        values: {
          type: 'object',
          description: 'Fields and new values. Example: {"email": "new@email.com", "phone": "+1 555 0100"}',
        },
      },
      required: ['model', 'id', 'values'],
    },
  },
  {
    name: 'delete_record',
    description:
      'Delete a record from Odoo. This action cannot be undone. Technical models (ir.*, base.automation, ' +
      'res.users, res.groups) cannot be deleted from.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name' },
        id: { type: 'number', description: 'Record ID to delete' },
      },
      required: ['model', 'id'],
    },
  },
  {
    name: 'list_models',
    description: 'List all available Odoo models accessible with the current user permissions.',
    inputSchema: {
      type: 'object',
      properties: {
        filter: {
          type: 'string',
          description: "Optional text filter applied to model name or label. Example: 'partner', 'sale', 'account'",
        },
        limit: { type: 'number', description: 'Max models to return (default: 100)', default: 100 },
      },
    },
  },
  {
    name: 'get_fields',
    description: 'Get the field schema of an Odoo model — useful before creating or updating records.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name' },
      },
      required: ['model'],
    },
  },
  {
    name: 'server_info',
    description: 'Get information about the connected Odoo instance (version, database name, server URL).',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'run_business_action',
    description:
      'Run an authorized Odoo business action on existing records — the equivalent of clicking a form button ' +
      'such as "Confirm" on a quotation or "Post" on an invoice. Only the actions configured by the server ' +
      `administrator can run. ${ALLOWED_METHODS_SUMMARY}`,
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name, e.g. "sale.order"' },
        method: { type: 'string', description: 'Action method name, e.g. "action_confirm"' },
        record_ids: {
          type: 'array',
          items: { type: 'integer' },
          minItems: 1,
          maxItems: MAX_ACTION_RECORDS,
          description: 'IDs of the records to run the action on',
        },
      },
      required: ['model', 'method', 'record_ids'],
    },
  },
];

// ============================================================
// MCP TOOL EXECUTION
// ============================================================

async function handleToolCall(
  toolName: string,
  input: Record<string, unknown>,
  client: OdooClient,
): Promise<unknown> {
  switch (toolName) {
    case 'search_records': {
      const { model, domain = [], fields = [], limit = 10, offset = 0, order, include_total = false } = input as {
        model: string; domain?: unknown[]; fields?: string[]; limit?: number; offset?: number; order?: string; include_total?: boolean;
      };
      const kwargs: Record<string, unknown> = { limit: Math.min(limit, 1000), offset };
      if ((fields as string[]).length > 0) kwargs.fields = fields;
      if (order) kwargs.order = order;
      const records = await client.callKw(model, 'search_read', [domain], kwargs);
      // total requires a second Odoo call — only fetch when explicitly requested
      const total = include_total ? await client.callKw(model, 'search_count', [domain], {}) : undefined;
      return { records, ...(total !== undefined ? { total } : {}), limit, offset };
    }

    case 'get_record': {
      const { model, id, fields = [] } = input as { model: string; id: number; fields?: string[] };
      const kwargs: Record<string, unknown> = {};
      if ((fields as string[]).length > 0) kwargs.fields = fields;
      const records = await client.callKw(model, 'read', [[id]], kwargs) as unknown[];
      if (!records || records.length === 0) throw new Error(`Record ${id} not found in model "${model}"`);
      return records[0];
    }

    case 'create_record': {
      const { model, values } = input as { model: string; values: Record<string, unknown> };
      await assertSafeValues(client, model, values, 'create');
      const id = await client.callKw(model, 'create', [values], {}) as number;
      return { id, success: true, message: `Created ${model} record with ID ${id}` };
    }

    case 'update_record': {
      const { model, id, values } = input as { model: string; id: number; values: Record<string, unknown> };
      if (!isRecordId(id)) throw new Error('"id" must be a positive integer.');
      await assertSafeValues(client, model, values, 'update');
      await client.callKw(model, 'write', [[id], values], {});
      return { success: true, message: `Updated ${model} record ${id}` };
    }

    case 'delete_record': {
      const { model, id } = input as { model: string; id: number };
      assertWritableModel(model);
      if (!isRecordId(id)) throw new Error('"id" must be a positive integer.');
      await client.callKw(model, 'unlink', [[id]], {});
      return { success: true, message: `Deleted ${model} record ${id}` };
    }

    case 'list_models': {
      const { filter = '', limit = 100 } = input as { filter?: string; limit?: number };
      const domain: unknown[] = filter
        ? ['|', ['model', 'ilike', filter], ['name', 'ilike', filter]]
        : [];
      const models = await client.callKw('ir.model', 'search_read', [domain], {
        fields: ['model', 'name', 'info'],
        order: 'model asc',
        limit: Math.min(limit, 500),
      });
      return { models, total: (models as unknown[]).length };
    }

    case 'get_fields': {
      const { model } = input as { model: string };
      const fields = await client.callKw(model, 'fields_get', [], {
        attributes: ['string', 'type', 'required', 'readonly', 'help', 'selection', 'relation'],
      });
      return { model, fields };
    }

    case 'server_info': {
      const version = await client.serverVersion();
      return {
        server_version: version.server_version,
        server_serie: version.server_serie,
        protocol_version: version.protocol_version,
        database: client.db,
        url: client.url,
      };
    }

    case 'run_business_action': {
      const { model, method, record_ids } = input as { model: unknown; method: unknown; record_ids: unknown };
      const action = `${String(model)}:${String(method)}`;

      // Hard filter: exact match against the server-side allowlist, before any call to Odoo.
      if (typeof model !== 'string' || typeof method !== 'string' || !ALLOWED_METHODS.has(action)) {
        console.warn(`[run_business_action] refused ${JSON.stringify(action)}`);
        throw new Error(`Action "${action}" is not authorized on this server. ${ALLOWED_METHODS_SUMMARY}`);
      }
      if (
        !Array.isArray(record_ids) || record_ids.length === 0 ||
        record_ids.length > MAX_ACTION_RECORDS || !record_ids.every(isRecordId)
      ) {
        throw new Error(`"record_ids" must be a list of 1 to ${MAX_ACTION_RECORDS} record IDs.`);
      }

      console.log(`[run_business_action] ${action} on ${record_ids.length} record(s)`);
      // Only the record IDs are sent: no free arguments, empty Odoo context.
      const result = await client.callKw(model, method, [record_ids], {});

      if (isPlainObject(result) && typeof result.type === 'string' && result.type.startsWith('ir.actions.')) {
        return {
          result,
          note:
            'The action returned an Odoo window or action (e.g. a wizard) instead of completing. ' +
            'It needs further steps that this tool does not perform.',
        };
      }
      return { result };
    }

    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

// ============================================================
// MCP HTTP HANDLER
// ============================================================

function extractBearerToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  return auth.slice(7);
}

function mcpHandler(req: Request, res: Response): void {
  const token = extractBearerToken(req);
  const stored = token ? accessTokens.get(token) : null;
  const ctx = stored?.ctx ?? null;

  // Always use the same resource_metadata URL regardless of which path was hit.
  // Using two different URLs would cause Dust to treat / and /mcp as separate OAuth
  // resources, launching two flows and creating duplicate MCP connections.
  const metadataPath = `${BASE_URL}/.well-known/oauth-protected-resource`;

  const sendUnauthorized = (description: string) =>
    res.status(401)
      .set('WWW-Authenticate', `Bearer resource_metadata="${metadataPath}"`)
      .json({ error: 'unauthorized', error_description: description });

  if (!ctx) {
    sendUnauthorized('Valid Bearer token required');
    return;
  }

  if (req.method === 'GET') {
    res.status(405).set('Allow', 'POST').json({ error: 'method_not_allowed', error_description: 'MCP requires POST requests' });
    return;
  }

  const { method, params, id } = req.body as { method: string; params?: Record<string, unknown>; id?: unknown };

  if (id === undefined) {
    res.status(204).send();
    return;
  }

  const ok = (result: unknown) => res.json({ jsonrpc: '2.0', id, result });
  const mcpError = (code: number, message: string) =>
    res.json({ jsonrpc: '2.0', id, error: { code, message } });

  const client = new OdooClient(ctx);

  void (async () => {
    switch (method) {
      case 'initialize':
        ok({
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'odoo-mcp-oauth', version: '1.0.0' },
        });
        break;

      case 'ping':
        ok({});
        break;

      case 'tools/list':
        ok({ tools: MCP_TOOLS });
        break;

      case 'tools/call': {
        const { name, arguments: args = {} } = (params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
        if (!name) { mcpError(-32602, 'Missing tool name'); break; }
        try {
          const result = await handleToolCall(name, args, client);
          ok({ content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        } catch (err: unknown) {
          if (err instanceof OdooSessionExpiredError) {
            // Remove the stale token and trigger Dust's OAuth reconnect flow
            if (token) accessTokens.delete(token);
            sendUnauthorized('Odoo session expired — please reconnect');
            return;
          }
          ok({
            content: [{ type: 'text', text: `Error: ${extractErrorMessage(err)}` }],
            isError: true,
          });
        }
        break;
      }

      default:
        mcpError(-32601, `Method not found: ${method}`);
    }
  })().catch((err: unknown) => {
    console.error('MCP handler error:', err);
    mcpError(-32603, 'Internal server error');
  });
}

app.all('/mcp', mcpLimiter, mcpHandler);

// GET / is a public status page — intentionally no auth required.
// Previously app.all('/', mcpHandler) caused Dust to see / and /mcp as two
// separate OAuth resources, triggering two auth flows and creating duplicate
// MCP connections. Now only /mcp is the canonical MCP endpoint.
app.get('/', (_req, res) => res.json({ status: 'ok', server: 'odoo-mcp-oauth', version: '1.0.0' }));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ============================================================
// HELPERS
// ============================================================

function extractErrorMessage(err: unknown, fallback = 'An unknown error occurred'): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  const e = err as { response?: { data?: { error?: { data?: { message?: string }; message?: string } } }; message?: string };
  return e?.response?.data?.error?.data?.message
    ?? e?.response?.data?.error?.message
    ?? e?.message
    ?? fallback;
}

function esc(s: string): string {
  return (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ============================================================
// HTML CREDENTIAL FORM
// ============================================================

function renderConnectForm(
  state: string,
  prefill: { url?: string; db?: string; username?: string } = {},
  error?: string,
): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Connect to Odoo</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0eff4;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{background:#fff;border-radius:16px;padding:40px;width:100%;max-width:440px;box-shadow:0 4px 32px rgba(0,0,0,.1)}
    .logo{text-align:center;margin-bottom:20px}
    h1{font-size:22px;font-weight:700;text-align:center;color:#111;margin-bottom:6px}
    .sub{font-size:14px;color:#666;text-align:center;line-height:1.5;margin-bottom:28px}
    .err{background:#fff5f5;border:1px solid #fca5a5;border-radius:8px;padding:12px 14px;color:#b91c1c;font-size:13px;line-height:1.5;margin-bottom:20px}
    .section{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;margin-bottom:12px}
    label{display:block;font-size:13px;font-weight:600;color:#374151;margin-bottom:5px}
    input{width:100%;padding:10px 13px;border:1.5px solid #e5e7eb;border-radius:8px;font-size:14px;color:#111;outline:none;transition:.15s border-color,.15s box-shadow}
    input:focus{border-color:#714B67;box-shadow:0 0 0 3px rgba(113,75,103,.12)}
    .field{margin-bottom:16px}
    .hint{margin-top:4px;font-size:12px;color:#9ca3af;line-height:1.4}
    hr{border:none;border-top:1.5px solid #f3f4f6;margin:20px 0}
    .btn{width:100%;padding:12px;background:#714B67;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:.15s background;margin-top:4px}
    .btn:hover{background:#5d3a55}
    .btn:disabled{background:#d1d5db;cursor:not-allowed}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg width="52" height="52" viewBox="0 0 52 52" xmlns="http://www.w3.org/2000/svg">
      <rect width="52" height="52" rx="12" fill="#714B67"/>
      <text x="26" y="39" font-size="30" font-family="sans-serif" font-weight="900" fill="#fff" text-anchor="middle">O</text>
    </svg>
  </div>
  <h1>Connect to Odoo</h1>
  <p class="sub">Enter your Odoo credentials to connect your AI assistant to your Odoo instance.</p>
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <form action="${BASE_URL}/authorize/submit" method="post" id="f">
    <input type="hidden" name="state" value="${esc(state)}">

    <div class="section">Odoo Instance</div>
    <div class="field">
      <label for="u">Odoo URL</label>
      <input type="url" id="u" name="odoo_url" placeholder="https://mycompany.odoo.com" value="${esc(prefill.url ?? '')}" required autocomplete="url">
    </div>
    <div class="field">
      <label for="d">Database name <span style="font-weight:400;color:#9ca3af">(optional)</span></label>
      <input type="text" id="d" name="odoo_db" placeholder="Auto-detect" value="${esc(prefill.db ?? '')}">
      <p class="hint">Leave empty to auto-detect. Required if you have multiple databases.</p>
    </div>

    <hr>
    <div class="section">Credentials</div>
    <div class="field">
      <label for="usr">Email / Username</label>
      <input type="email" id="usr" name="odoo_user" placeholder="admin@mycompany.com" value="${esc(prefill.username ?? '')}" required autocomplete="email">
    </div>
    <div class="field">
      <label for="pwd">Password</label>
      <input type="password" id="pwd" name="odoo_password" required autocomplete="current-password">
    </div>

    <button class="btn" type="submit" id="btn">Connect to Odoo</button>
  </form>
</div>
<script>
  document.getElementById('f').addEventListener('submit', function() {
    var b = document.getElementById('btn');
    b.disabled = true;
    b.textContent = 'Connecting…';
  });
</script>
</body>
</html>`;
}

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, () => {
  console.log(`\nOdoo MCP OAuth Server`);
  console.log(`  MCP endpoint      : ${BASE_URL}/mcp`);
  console.log(`  OAuth discovery   : ${BASE_URL}/.well-known/oauth-authorization-server`);
  console.log(`  Health            : ${BASE_URL}/health`);
  console.log(`  Business actions  : ${ALLOWED_METHODS.size === 0 ? 'none authorized' : [...ALLOWED_METHODS].join(', ')}\n`);
});
