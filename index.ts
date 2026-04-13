/**
 * Odoo MCP OAuth Server
 *
 * A multi-user OAuth proxy MCP server that connects Dust (or any MCP client)
 * to Odoo via a native "Connect" button. Each user authenticates independently
 * with their own Odoo credentials (URL + API key).
 *
 * Architecture:
 *   Dust ←→ [This server (OAuth proxy + MCP)] ←→ Odoo JSON-RPC
 *
 * OAuth flow implemented:
 *   RFC 9728: Protected Resource Metadata
 *   RFC 8414: Authorization Server Metadata
 *   RFC 7591: Dynamic Client Registration
 *   RFC 7636: PKCE
 *   The /authorize endpoint serves an HTML form to capture Odoo credentials,
 *   since Odoo has no standard OAuth2 authorization server.
 */

import express, { type Request, type Response } from 'express';
import cors from 'cors';
import axios from 'axios';
import { createHash, randomBytes } from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = parseInt(process.env.PORT ?? '3000');
const BASE_URL = (process.env.BASE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, '');

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowedHeaders: ['*'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
// TYPES
// ============================================================

interface OdooContext {
  url: string;
  db: string;
  uid: number;
  apiKey: string; // password or API key (used as RPC password)
}

interface PendingAuth {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
}

interface AuthCode {
  clientId: string;
  odooCtx: OdooContext;
  codeChallenge: string;
  codeChallengeMethod: string;
  redirectUri: string;
  createdAt: number;
}

// ============================================================
// IN-MEMORY STORES
// Sufficient for most deployments — Dust re-authenticates on server restart.
// ============================================================

const registeredClients = new Map<string, { clientSecret: string; redirectUris: string[] }>();
const pendingAuths = new Map<string, PendingAuth>();    // keyed by state
const authCodes = new Map<string, AuthCode>();          // keyed by code
const accessTokens = new Map<string, OdooContext>();    // keyed by bearer token

// Expire old auth codes every 10 minutes
setInterval(() => {
  const cutoff = Date.now() - 600_000;
  for (const [k, v] of authCodes) {
    if (v.createdAt < cutoff) authCodes.delete(k);
  }
}, 600_000);

// ============================================================
// PKCE VERIFICATION (RFC 7636)
// ============================================================

function verifyPKCE(verifier: string, challenge: string, method: string): boolean {
  if (method === 'S256') {
    const hash = createHash('sha256').update(verifier).digest('base64url');
    return hash === challenge;
  }
  return verifier === challenge; // 'plain'
}

// ============================================================
// ODOO JSON-RPC CLIENT
// Uses the /jsonrpc endpoint (works on Odoo 14–18, self-hosted + SaaS).
// Each call passes db + uid + apiKey — no web session required.
// ============================================================

class OdooClient {
  private readonly baseUrl: string;
  readonly db: string;
  readonly url: string;

  constructor(private readonly ctx: OdooContext) {
    this.baseUrl = ctx.url.replace(/\/$/, '');
    this.db = ctx.db;
    this.url = ctx.url;
  }

  /** Low-level JSON-RPC call to /jsonrpc */
  async rpc(service: string, method: string, args: unknown[]): Promise<unknown> {
    const resp = await axios.post(
      `${this.baseUrl}/jsonrpc`,
      { jsonrpc: '2.0', method: 'call', id: Date.now(), params: { service, method, args } },
      { headers: { 'Content-Type': 'application/json' }, timeout: 30_000 },
    );
    if (resp.data.error) {
      const msg: string = (resp.data.error.data?.message as string) ?? (resp.data.error.message as string) ?? 'Odoo RPC error';
      throw new Error(msg);
    }
    return resp.data.result;
  }

  /** Call a model method via execute_kw */
  async executeKw(
    model: string,
    method: string,
    args: unknown[],
    kwargs: Record<string, unknown> = {},
  ): Promise<unknown> {
    return this.rpc('object', 'execute_kw', [
      this.ctx.db, this.ctx.uid, this.ctx.apiKey, model, method, args, kwargs,
    ]);
  }

  /** Get Odoo server version info */
  async serverVersion(): Promise<Record<string, unknown>> {
    return this.rpc('common', 'version', []) as Promise<Record<string, unknown>>;
  }
}

// ============================================================
// ODOO AUTHENTICATION HELPERS
// ============================================================

/** Authenticate with Odoo JSON-RPC and return the UID. */
async function odooAuthenticate(url: string, db: string, username: string, apiKey: string): Promise<number> {
  const baseUrl = url.replace(/\/$/, '');
  const resp = await axios.post(
    `${baseUrl}/jsonrpc`,
    {
      jsonrpc: '2.0', method: 'call', id: 1,
      params: { service: 'common', method: 'authenticate', args: [db, username, apiKey, {}] },
    },
    { headers: { 'Content-Type': 'application/json' }, timeout: 10_000 },
  );

  if (resp.data.error) {
    const msg: string = (resp.data.error.data?.message as string) ?? 'Authentication failed';
    throw new Error(msg);
  }

  const uid: number = resp.data.result as number;
  if (!uid) throw new Error('Invalid credentials — authentication returned UID=0. Check your username and API key/password.');
  return uid;
}

/** Try to auto-detect the database name (works when only 1 DB exists). */
async function detectDb(url: string): Promise<string | null> {
  try {
    const resp = await axios.post(
      `${url.replace(/\/$/, '')}/web/database/list`,
      { jsonrpc: '2.0', method: 'call', id: 1, params: {} },
      { headers: { 'Content-Type': 'application/json' }, timeout: 5_000 },
    );
    const dbs: string[] = resp.data.result as string[];
    if (Array.isArray(dbs) && dbs.length === 1) return dbs[0];
    return null;
  } catch {
    return null;
  }
}

// ============================================================
// OAUTH ENDPOINTS — these give Dust the native "Connect" button
// ============================================================

/** RFC 9728 — OAuth 2.0 Protected Resource Metadata */
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json({
    resource: BASE_URL,
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
    code_challenge_methods_supported: ['S256', 'plain'],
  });
});

/** RFC 7591 — Dynamic Client Registration */
app.post('/register', (req, res) => {
  const { redirect_uris = [], client_name } = req.body as { redirect_uris?: string[]; client_name?: string };
  const clientId = randomBytes(16).toString('hex');
  const clientSecret = randomBytes(32).toString('hex');
  registeredClients.set(clientId, { clientSecret, redirectUris: redirect_uris });
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

/**
 * Authorization endpoint — serves an HTML credential form.
 * Odoo has no standard OAuth2 flow, so we capture credentials directly
 * and validate them against the Odoo JSON-RPC authenticate endpoint.
 */
app.get('/authorize', (req, res) => {
  const q = req.query as Record<string, string>;
  const { state, redirect_uri, client_id, code_challenge, code_challenge_method } = q;

  if (!state || !redirect_uri || !code_challenge) {
    return res.status(400).send('<h2>Missing required OAuth parameters (state, redirect_uri, code_challenge).</h2>');
  }

  pendingAuths.set(state, {
    clientId: client_id ?? '',
    redirectUri: redirect_uri,
    state,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method ?? 'S256',
  });

  res.send(renderConnectForm(state));
});

/** Handle the credential form submission */
app.post('/authorize/submit', async (req, res) => {
  const { state, odoo_url, odoo_db, odoo_user, odoo_apikey } = req.body as Record<string, string>;

  const pending = pendingAuths.get(state);
  if (!pending) {
    return res.status(400).send('<h2>Session expired or invalid. Please try connecting again from Dust.</h2>');
  }

  const url = (odoo_url ?? '').trim().replace(/\/$/, '');
  let db = (odoo_db ?? '').trim();
  const username = (odoo_user ?? '').trim();
  const apiKey = (odoo_apikey ?? '').trim();

  if (!url || !username || !apiKey) {
    return res.send(renderConnectForm(state, { url, db, username }, 'Odoo URL, email, and API key are required.'));
  }

  try {
    // Auto-detect database when not provided
    if (!db) {
      const detected = await detectDb(url);
      if (!detected) {
        return res.send(renderConnectForm(
          state, { url, db, username },
          'Could not auto-detect the database name. Please enter it manually.',
        ));
      }
      db = detected;
    }

    // Validate credentials against Odoo
    const uid = await odooAuthenticate(url, db, username, apiKey);
    const odooCtx: OdooContext = { url, db, uid, apiKey };

    // Store auth code (contains the pending PKCE info for /token verification)
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

    // Always redirect back to Dust — never show a debug page here
    const redirectUrl = new URL(pending.redirectUri);
    redirectUrl.searchParams.set('code', code);
    redirectUrl.searchParams.set('state', state);
    res.redirect(redirectUrl.toString());

  } catch (err: unknown) {
    const msg = extractErrorMessage(err, 'Authentication failed. Please check your credentials.');
    res.send(renderConnectForm(state, { url, db, username }, msg));
  }
});

/** Token endpoint — exchanges auth code for bearer token */
app.post('/token', (req, res) => {
  const { grant_type, code, code_verifier } = req.body as Record<string, string>;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const authCode = authCodes.get(code);
  if (!authCode) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' });
  }

  // PKCE verification
  if (code_verifier) {
    if (!verifyPKCE(code_verifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }
  }

  const accessToken = randomBytes(32).toString('hex');
  accessTokens.set(accessToken, authCode.odooCtx);
  authCodes.delete(code);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 86_400 * 30, // 30 days
    scope: 'odoo',
  });
});

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
    description: 'Create a new record in an Odoo model. Returns the ID of the created record.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name' },
        values: {
          type: 'object',
          description: "Field values for the new record. Example: {\"name\": \"ACME Corp\", \"is_company\": true}",
        },
      },
      required: ['model', 'values'],
    },
  },
  {
    name: 'update_record',
    description: 'Update an existing Odoo record.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name' },
        id: { type: 'number', description: 'Record ID to update' },
        values: {
          type: 'object',
          description: "Fields and new values. Example: {\"email\": \"new@email.com\", \"phone\": \"+1 555 0100\"}",
        },
      },
      required: ['model', 'id', 'values'],
    },
  },
  {
    name: 'delete_record',
    description: 'Delete a record from Odoo. This action cannot be undone.',
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
    description: 'List all available Odoo models (technical models) accessible with the current user permissions.',
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
    name: 'execute_method',
    description: 'Execute any Odoo model method directly (advanced). Useful for calling business methods like confirm(), action_validate(), etc.',
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string', description: 'Odoo model name' },
        method: { type: 'string', description: "Method name. Examples: 'action_confirm', 'action_validate', 'name_search'" },
        args: {
          type: 'array',
          description: 'Positional arguments (first arg is usually a list of IDs). Example: [[42]]',
          default: [],
        },
        kwargs: {
          type: 'object',
          description: 'Keyword arguments. Example: {"context": {"lang": "fr_FR"}}',
          default: {},
        },
      },
      required: ['model', 'method'],
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
      const { model, domain = [], fields = [], limit = 10, offset = 0, order } = input as {
        model: string; domain?: unknown[]; fields?: string[]; limit?: number; offset?: number; order?: string;
      };
      const kwargs: Record<string, unknown> = { limit: Math.min(limit, 1000), offset };
      if ((fields as string[]).length > 0) kwargs.fields = fields;
      if (order) kwargs.order = order;
      const records = await client.executeKw(model, 'search_read', [domain], kwargs);
      const total = await client.executeKw(model, 'search_count', [domain], {});
      return { records, total, limit, offset };
    }

    case 'get_record': {
      const { model, id, fields = [] } = input as { model: string; id: number; fields?: string[] };
      const kwargs: Record<string, unknown> = {};
      if ((fields as string[]).length > 0) kwargs.fields = fields;
      const records = await client.executeKw(model, 'read', [[id]], kwargs) as unknown[];
      if (!records || records.length === 0) throw new Error(`Record ${id} not found in model "${model}"`);
      return (records as unknown[])[0];
    }

    case 'create_record': {
      const { model, values } = input as { model: string; values: Record<string, unknown> };
      const id = await client.executeKw(model, 'create', [values], {}) as number;
      return { id, success: true, message: `Created ${model} record with ID ${id}` };
    }

    case 'update_record': {
      const { model, id, values } = input as { model: string; id: number; values: Record<string, unknown> };
      await client.executeKw(model, 'write', [[id], values], {});
      return { success: true, message: `Updated ${model} record ${id}` };
    }

    case 'delete_record': {
      const { model, id } = input as { model: string; id: number };
      await client.executeKw(model, 'unlink', [[id]], {});
      return { success: true, message: `Deleted ${model} record ${id}` };
    }

    case 'list_models': {
      const { filter = '', limit = 100 } = input as { filter?: string; limit?: number };
      const domain: unknown[] = filter
        ? ['|', ['model', 'ilike', filter], ['name', 'ilike', filter]]
        : [];
      const models = await client.executeKw('ir.model', 'search_read', [domain], {
        fields: ['model', 'name', 'info'],
        order: 'model asc',
        limit: Math.min(limit, 500),
      });
      return { models, total: (models as unknown[]).length };
    }

    case 'get_fields': {
      const { model } = input as { model: string };
      const fields = await client.executeKw(model, 'fields_get', [], {
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

    case 'execute_method': {
      const { model, method, args = [], kwargs = {} } = input as {
        model: string; method: string; args?: unknown[]; kwargs?: Record<string, unknown>;
      };
      const result = await client.executeKw(model, method, args as unknown[], kwargs);
      return { result };
    }

    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

// ============================================================
// MCP HTTP HANDLER
// Implements the MCP protocol over HTTP POST manually (no SDK transport).
// Bearer token → OdooContext lookup → execute tool.
// ============================================================

function extractBearerToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  return auth.slice(7);
}

function mcpHandler(req: Request, res: Response): void {
  // Unauthenticated requests → 401 with WWW-Authenticate (triggers Dust Connect button)
  const token = extractBearerToken(req);
  const ctx = token ? accessTokens.get(token) : null;

  if (!ctx) {
    res.status(401)
      .set('WWW-Authenticate', `Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`)
      .json({ error: 'unauthorized', error_description: 'Valid Bearer token required' });
    return;
  }

  // GET requests — connectivity check
  if (req.method === 'GET') {
    res.json({ status: 'ok', server: 'odoo-mcp-oauth', version: '1.0.0' });
    return;
  }

  const { method, params, id } = req.body as { method: string; params?: Record<string, unknown>; id?: unknown };

  // Notifications have no id — just ack them
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

// MCP served at both / and /mcp (Dust uses base URL /)
app.all('/mcp', mcpHandler);
app.all('/', mcpHandler);

// Health check endpoint
app.get('/health', (_req, res) => res.json({ status: 'ok', connectedUsers: accessTokens.size }));

// ============================================================
// HELPERS
// ============================================================

function extractErrorMessage(err: unknown, fallback = 'An unknown error occurred'): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  // axios error with Odoo error body
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
  <form action="/authorize/submit" method="post" id="f">
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
      <label for="key">API Key or Password</label>
      <input type="password" id="key" name="odoo_apikey" required autocomplete="current-password">
      <p class="hint">Generate an API key: Odoo Settings → Users → Your profile → API Keys tab. Using API keys is more secure than passwords.</p>
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
  console.log(`  MCP endpoint : ${BASE_URL}/`);
  console.log(`  OAuth discovery : ${BASE_URL}/.well-known/oauth-authorization-server`);
  console.log(`  Health : ${BASE_URL}/health\n`);
});
