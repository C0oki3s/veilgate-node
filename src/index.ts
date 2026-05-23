/**
 * @veilgate/node — server-side SDK
 *
 * Three responsibilities:
 *
 * 1. Outgoing auth — sign or attach tokens to server-to-server calls:
 *      bearerFetch("vg_live_abc123")
 *      hmacFetch({ clientId: "payments", secret: process.env.VG_SECRET! })
 *
 * 2. Decoy response headers — add tarpit breadcrumbs to your API's outgoing
 *    responses so agents probing the API discover and follow realistic paths
 *    into VeilGate's tarpit instead of real endpoints:
 *      app.use(decoyMiddleware({ baseURL: "https://api.example.com" }))
 *
 * 3. Signature verification — validate inbound HMAC signatures in tests or
 *    custom middleware.
 */

import { createHmac, timingSafeEqual, createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * One bait endpoint entry from /__veilgate/.well-known tarpit.paths,
 * or supplied manually via DecoyOptions.paths.
 */
export interface TarpitPathEntry {
  path: string;
  /** Human-readable service label, e.g. "vault", "spring-actuator". */
  service?: string;
}

export interface DecoyOptions {
  /**
   * Base URL of the VeilGate-protected server.
   * Used to fetch /__veilgate/.well-known for decoy path discovery.
   * Example: "https://api.example.com". Defaults to "" (same host).
   */
  baseURL?: string;

  /**
   * Override the decoy path list entirely. When omitted the middleware
   * fetches paths from /__veilgate/.well-known on first use, falling back
   * to the built-in pool if discovery fails.
   */
  paths?: TarpitPathEntry[];

  /**
   * Number of decoy paths to inject per response. Default: 3.
   * Higher values expose more breadcrumbs but add header bloat.
   */
  count?: number;

  /**
   * Inject a `Link:` header with RFC 8288 relation types pointing to decoy
   * paths. Link headers are followed by crawlers and API-probing scanners.
   * Default: true.
   */
  linkHeader?: boolean;

  /**
   * Inject service-hinting headers (X-Api-Documentation, X-Debug-Endpoint)
   * when matching paths are found in the picked set. Default: true.
   */
  serviceHeaders?: boolean;

  /** Override the fetch implementation used for .well-known discovery. */
  fetchImpl?: typeof fetch;
}

/**
 * The object returned by decoyMiddleware(). Callable as a standard
 * Express/Fastify/Node middleware function, and also exposes runtime
 * controls for enabling, disabling, and reconfiguring decoys.
 */
export interface DecoyMiddlewareFn {
  (req: unknown, res: { setHeader(name: string, value: string): void }, next: () => void): void;
  /**
   * Enable or disable decoy header injection without recreating the middleware.
   * When disabled, next() is called immediately with no headers added.
   */
  setEnabled(enabled: boolean): void;
  /**
   * Merge new options into the running middleware. Changing baseURL or paths
   * clears the resolved-path cache so discovery runs again on the next request.
   */
  update(opts: Partial<DecoyOptions>): void;
}

export interface BearerOptions {
  /** The raw token value. Attached as "Authorization: Bearer <token>". */
  token: string;
  /** Override the Authorization header name. Default: "Authorization". */
  header?: string;
  /** Override the scheme prefix. Default: "Bearer". Pass "" for raw-token mode. */
  scheme?: string;
}

export interface HMACOptions {
  /** The client identifier sent in X-Veilgate-Client. */
  clientId: string;
  /** The shared secret. Keep in an environment variable — never in source. */
  secret: string;
  /** Override the signature header. Default: "X-Veilgate-Signature". */
  signatureHeader?: string;
  /** Override the client-id header. Default: "X-Veilgate-Client". */
  clientHeader?: string;
  /**
   * Replay window in seconds. Requests with a timestamp older than this
   * (or in the future by more than this) are rejected. Default: 300 (5 min).
   * Match the server-side tolerance configured on the VeilGate instance.
   */
  replayWindow?: number;
}

export interface SignedHeaders {
  [header: string]: string;
}

// ---------------------------------------------------------------------------
// Bearer
// ---------------------------------------------------------------------------

/**
 * Returns a `fetch`-compatible function that attaches a bearer token to
 * every request. Drop-in replacement for `globalThis.fetch`.
 *
 * ```ts
 * const apiFetch = bearerFetch("vg_live_abc123");
 * const resp = await apiFetch("https://api.example.com/widgets");
 * ```
 */
export function bearerFetch(
  tokenOrOpts: string | BearerOptions,
  fetchImpl: typeof fetch = globalThis.fetch,
): typeof fetch {
  const opts = typeof tokenOrOpts === "string"
    ? { token: tokenOrOpts }
    : tokenOrOpts;
  const header = opts.header ?? "Authorization";
  const scheme = opts.scheme === undefined ? "Bearer" : opts.scheme;
  const value = scheme ? `${scheme} ${opts.token}` : opts.token;

  return async function bearerFetchImpl(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    const headers = new Headers((init ?? {}).headers);
    if (!headers.has(header)) {
      headers.set(header, value);
    }
    return fetchImpl(input, { ...(init ?? {}), headers });
  };
}

// ---------------------------------------------------------------------------
// HMAC signing
// ---------------------------------------------------------------------------

/**
 * Computes the `X-Veilgate-Signature` value for a request.
 *
 * Canonical string: `<unix-ts>.<METHOD>.<path>.<hex(sha256(body))>`
 * Signature:        `t=<ts>,v1=<hex(HMAC-SHA256(secret, canonical))>`
 *
 * This matches the canonical string format expected by VeilGate's
 * `HMACVerifier` on the server side.
 *
 * @param secret     The shared HMAC secret.
 * @param method     HTTP method (GET, POST, …).
 * @param path       Request path including query string (e.g. "/api/v1/data?foo=bar").
 * @param body       Request body bytes. Pass empty Buffer for requests without a body.
 * @param timestamp  Unix timestamp (seconds). Defaults to Date.now()/1000.
 */
export function signRequest(
  secret: string,
  method: string,
  path: string,
  body: Buffer | Uint8Array | string = Buffer.alloc(0),
  timestamp?: number,
): string {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const bodyBuf =
    typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
  const bodyHash = createHash("sha256").update(bodyBuf).digest("hex");
  const canonical = `${ts}.${method.toUpperCase()}.${path}.${bodyHash}`;
  const mac = createHmac("sha256", secret).update(canonical).digest("hex");
  return `t=${ts},v1=${mac}`;
}

/**
 * Returns an object of headers that authenticate this request via HMAC.
 * Attach them alongside your other headers.
 *
 * ```ts
 * const sig = signHeaders({ clientId: "pay", secret: process.env.VG_SECRET! }, "POST", "/charge", body);
 * const resp = await fetch(url, { method: "POST", body, headers: sig });
 * ```
 */
export function signHeaders(
  opts: HMACOptions,
  method: string,
  path: string,
  body: Buffer | Uint8Array | string = Buffer.alloc(0),
  timestamp?: number,
): SignedHeaders {
  const sigHeader = opts.signatureHeader ?? "X-Veilgate-Signature";
  const clientHeader = opts.clientHeader ?? "X-Veilgate-Client";
  return {
    [sigHeader]: signRequest(opts.secret, method, path, body, timestamp),
    [clientHeader]: opts.clientId,
  };
}

/**
 * Returns a `fetch`-compatible function that signs every request with
 * HMAC-SHA256 before sending. Drop-in replacement for `globalThis.fetch`.
 *
 * The function reads the request body to compute the body hash, buffers
 * it in memory, and passes a fresh readable copy to the underlying fetch.
 * This is transparent to the caller but means you cannot pass a streaming
 * body — convert it to a Buffer first.
 *
 * ```ts
 * const apiFetch = hmacFetch({ clientId: "payments", secret: process.env.VG_SECRET! });
 * const resp = await apiFetch("https://api.example.com/charge", {
 *   method: "POST",
 *   body: JSON.stringify({ amount: 100 }),
 *   headers: { "Content-Type": "application/json" },
 * });
 * ```
 */
export function hmacFetch(
  opts: HMACOptions,
  fetchImpl: typeof fetch = globalThis.fetch,
): typeof fetch {
  return async function hmacFetchImpl(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url,
    );
    const method = init?.method ?? (typeof input !== "string" && !(input instanceof URL) ? (input as Request).method : "GET");
    const path = url.pathname + url.search;

    // Buffer the body so we can hash it.
    let bodyBuf: Uint8Array = new Uint8Array(0);
    if (init?.body != null) {
      bodyBuf = await _readBody(init.body);
    }

    const sigHeaders = signHeaders(opts, method, path, bodyBuf);
    const headers = new Headers((init ?? {}).headers);
    for (const [k, v] of Object.entries(sigHeaders)) {
      headers.set(k, v);
    }

    return fetchImpl(input, {
      ...(init ?? {}),
      body: bodyBuf.length > 0 ? bodyBuf : init?.body,
      headers,
    });
  };
}

// ---------------------------------------------------------------------------
// Decoy response headers
//
// Adds realistic-looking HTTP response headers to your API's outgoing
// responses. Agents (bots, scanners, LLM tool-callers) probing the API see
// these headers and follow the paths into VeilGate's tarpit instead of
// discovering real internal endpoints.
//
// Works in any context where the server sends HTTP responses: SPA backend,
// REST API, GraphQL, gRPC-gateway — anything with res.setHeader().
// ---------------------------------------------------------------------------

const DISCOVERY_PATH = "/__veilgate/.well-known";

// Default pool used when discovery fails or baseURL is not configured.
// Mirror of the browser SDK defaults so both surfaces expose the same baits.
const DEFAULT_DECOY_PATHS: TarpitPathEntry[] = [
  { path: "/api/v1/fetch", service: "ssrf-bait" },
  { path: "/api/proxy", service: "ssrf-bait" },
  { path: "/.env.local", service: "secrets" },
  { path: "/.env.production", service: "secrets" },
  { path: "/config/secrets.yml", service: "secrets" },
  { path: "/config/master.key", service: "rails-credentials" },
  { path: "/.git/config", service: "git" },
  { path: "/.github/workflows/deploy.yml", service: "github-actions" },
  { path: "/api/internal/debug", service: "debug-panel" },
  { path: "/api/internal/rpc", service: "debug-panel" },
  { path: "/prisma-studio", service: "prisma" },
  { path: "/graphql", service: "graphql" },
  { path: "/telescope", service: "laravel-telescope" },
  { path: "/horizon", service: "laravel-horizon" },
  { path: "/api/docs/openapi.json", service: "openapi" },
  { path: "/swagger-ui.html", service: "swagger" },
  { path: "/actuator/env", service: "spring-actuator" },
  { path: "/actuator/heapdump", service: "spring-actuator" },
  { path: "/v1/secret/data/prod", service: "vault" },
  { path: "/v1/auth/token/lookup-self", service: "vault" },
  { path: "/consul/v1/kv/", service: "consul" },
  { path: "/__grafana/api/datasources/proxy/1/query", service: "grafana" },
  { path: "/_cat/indices", service: "elasticsearch" },
  { path: "/api/webhooks/stripe/test", service: "stripe" },
  { path: "/oauth2/token", service: "oauth2" },
  { path: "/api/ai/completions", service: "openai-proxy" },
  { path: "/v1/models", service: "openai-proxy" },
  { path: "/api/v1/secrets", service: "kubernetes" },
  { path: "/bitbucket-pipelines.yml", service: "ci" },
  { path: "/Jenkinsfile", service: "ci" },
];

// Module-level cache: baseURL → { paths, fetchedAt }
// TTL matches the .well-known Cache-Control max-age=60 the server sets.
const _discoveryCache = new Map<string, { paths: TarpitPathEntry[]; fetchedAt: number }>();
const CACHE_TTL_MS = 60_000;

/**
 * Fetches /__veilgate/.well-known and returns the tarpit path list.
 * Results are cached for 60 seconds (matching the server's Cache-Control).
 * Falls back to an empty array on any error — callers should provide a
 * fallback via DEFAULT_DECOY_PATHS.
 *
 * ```ts
 * const paths = await fetchDecoyPaths("https://api.example.com");
 * ```
 */
export async function fetchDecoyPaths(
  baseURL = "",
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<TarpitPathEntry[]> {
  const key = baseURL;
  const cached = _discoveryCache.get(key);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.paths;
  }
  try {
    const resp = await fetchImpl(baseURL + DISCOVERY_PATH, {
      headers: { Accept: "application/json" },
    });
    if (!resp.ok) return [];
    const doc = await resp.json() as { tarpit?: { paths?: TarpitPathEntry[] } };
    const paths = doc?.tarpit?.paths ?? [];
    _discoveryCache.set(key, { paths, fetchedAt: Date.now() });
    return paths;
  } catch {
    return [];
  }
}

/**
 * Builds a plain-object map of HTTP response headers containing decoy
 * breadcrumbs. Apply these to any outgoing response so agents probing
 * the API discover tarpit paths instead of real internal endpoints.
 *
 * Header strategy:
 *   - `Link:` RFC 8288 header — crawlers and API clients follow rel links.
 *   - `X-Api-Documentation:` — common in dev APIs; scanners scrape it.
 *   - `X-Debug-Endpoint:` — looks like a leaked dev-mode hint.
 *
 * ```ts
 * const paths = await fetchDecoyPaths(baseURL);
 * const headers = decoyResponseHeaders(paths, { count: 3 });
 * // { Link: "</actuator/env>; rel=\"help\", ...", "X-Debug-Endpoint": "/api/internal/debug" }
 * ```
 */
export function decoyResponseHeaders(
  paths: TarpitPathEntry[],
  opts?: Pick<DecoyOptions, "count" | "linkHeader" | "serviceHeaders">,
): Record<string, string> {
  const pool = paths.length > 0 ? paths : DEFAULT_DECOY_PATHS;
  const count = Math.min(opts?.count ?? 3, pool.length);
  const picked = _pickRandom(pool, count);
  const headers: Record<string, string> = {};

  if (opts?.linkHeader !== false && picked.length > 0) {
    const RELS = ["help", "related", "about", "describedby"] as const;
    const parts = picked.map((p, i) => `<${p.path}>; rel="${RELS[i % RELS.length]}"`);
    headers["Link"] = parts.join(", ");
  }

  if (opts?.serviceHeaders !== false) {
    const docs = picked.find(
      (p) => p.service?.includes("openapi") || p.service?.includes("swagger") ||
             p.path.includes("openapi") || p.path.includes("swagger"),
    );
    if (docs) headers["X-Api-Documentation"] = docs.path;

    const debug = picked.find(
      (p) => p.service?.includes("debug") || p.service?.includes("panel") ||
             p.path.includes("debug") || p.path.includes("internal"),
    );
    if (debug) headers["X-Debug-Endpoint"] = debug.path;
  }

  return headers;
}

/**
 * Returns a framework-agnostic middleware that adds decoy response headers
 * to every outgoing response. Compatible with Express, Fastify, raw Node.js
 * http.Server, and any framework that exposes `res.setHeader()`.
 *
 * On first request the middleware fetches /__veilgate/.well-known to load
 * the operator-configured decoy paths. Results are cached for 60 s.
 * Passes a fallback built-in pool if discovery fails or baseURL is unset.
 *
 * ```ts
 * // Express
 * app.use(decoyMiddleware({ baseURL: "https://api.example.com" }));
 *
 * // Fastify
 * fastify.addHook("onSend", (req, reply, payload, done) => {
 *   const hdrs = decoyResponseHeaders(serverDecoyPaths, { count: 3 });
 *   for (const [k, v] of Object.entries(hdrs)) reply.header(k, v);
 *   done();
 * });
 *
 * // Raw Node http
 * server = http.createServer((req, res) => {
 *   middleware(req, res, () => { res.end(body); });
 * });
 * ```
 */
export function decoyMiddleware(opts?: DecoyOptions): DecoyMiddlewareFn {
  let _enabled = true;
  let _currentOpts: DecoyOptions = { ...opts };
  let _resolvedPaths: TarpitPathEntry[] | null = opts?.paths ?? null;

  const applyHeaders = (
    paths: TarpitPathEntry[],
    res: { setHeader(name: string, value: string): void },
    next: () => void,
  ) => {
    const hdrs = decoyResponseHeaders(paths, {
      count: _currentOpts.count,
      linkHeader: _currentOpts.linkHeader,
      serviceHeaders: _currentOpts.serviceHeaders,
    });
    for (const [name, value] of Object.entries(hdrs)) {
      res.setHeader(name, value);
    }
    next();
  };

  const fn = function vgDecoyMiddleware(
    _req: unknown,
    res: { setHeader(name: string, value: string): void },
    next: () => void,
  ): void {
    if (!_enabled) {
      next();
      return;
    }

    if (_resolvedPaths !== null) {
      applyHeaders(_resolvedPaths, res, next);
      return;
    }

    const baseURL = _currentOpts.baseURL ?? "";
    const fetchImpl = _currentOpts.fetchImpl ?? globalThis.fetch;

    // First request: discover paths from .well-known, then apply.
    // fetchDecoyPaths handles caching internally.
    fetchDecoyPaths(baseURL, fetchImpl).then((paths) => {
      _resolvedPaths = paths.length > 0 ? paths : DEFAULT_DECOY_PATHS;
      applyHeaders(_resolvedPaths, res, next);
    }).catch(() => {
      _resolvedPaths = DEFAULT_DECOY_PATHS;
      applyHeaders(_resolvedPaths, res, next);
    });
  } as DecoyMiddlewareFn;

  fn.setEnabled = (enabled: boolean): void => {
    _enabled = enabled;
  };

  fn.update = (newOpts: Partial<DecoyOptions>): void => {
    const prevBaseURL = _currentOpts.baseURL;
    const prevPaths = _currentOpts.paths;
    _currentOpts = { ..._currentOpts, ...newOpts };

    // Reset resolved cache when the path source changes so discovery
    // or the new explicit list is picked up on the next request.
    if ("paths" in newOpts) {
      _resolvedPaths = newOpts.paths ?? null;
    } else if ("baseURL" in newOpts && newOpts.baseURL !== prevBaseURL) {
      _resolvedPaths = null;
    } else if (prevPaths !== undefined && !("paths" in newOpts)) {
      // paths was previously set but not in the new opts — leave as-is.
    }
  };

  return fn;
}

// ---------------------------------------------------------------------------
// Verification helpers (for middleware / testing)
// ---------------------------------------------------------------------------

/**
 * Verifies an `X-Veilgate-Signature` header value against the expected
 * canonical string. Returns `true` only when the MAC is valid, the
 * timestamp is within the replay window, and both strings are compared
 * in constant time.
 *
 * Use this in integration tests or custom middleware that needs to check
 * VeilGate HMAC signatures from the receiving side.
 */
export function verifySignature(
  signature: string,
  secret: string,
  method: string,
  path: string,
  body: Buffer | Uint8Array | string = Buffer.alloc(0),
  opts?: { replayWindow?: number },
): boolean {
  const replayWindow = opts?.replayWindow ?? 300;
  const parsed = _parseSignature(signature);
  if (!parsed) return false;
  const { ts, mac } = parsed;

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > replayWindow) return false;

  const expected = signRequest(secret, method, path, body, ts);
  const expectedMac = _parseSignature(expected)?.mac ?? "";
  try {
    return timingSafeEqual(Buffer.from(mac, "hex"), Buffer.from(expectedMac, "hex"));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _pickRandom<T>(pool: T[], count: number): T[] {
  const src = [...pool];
  const out: T[] = [];
  while (src.length > 0 && out.length < count) {
    const i = Math.floor(Math.random() * src.length);
    out.push(src.splice(i, 1)[0]);
  }
  return out;
}

function _parseSignature(sig: string): { ts: number; mac: string } | null {
  const match = sig.match(/^t=(\d+),v1=([0-9a-f]+)$/);
  if (!match) return null;
  return { ts: parseInt(match[1], 10), mac: match[2] };
}

async function _readBody(body: NonNullable<RequestInit["body"]>): Promise<Uint8Array> {
  if (body instanceof ArrayBuffer) {
    return new Uint8Array(body);
  }
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }
  if (typeof body === "string") {
    return Buffer.from(body, "utf8");
  }
  if (body instanceof Blob) {
    return new Uint8Array(await body.arrayBuffer());
  }
  if (body instanceof URLSearchParams) {
    return Buffer.from(body.toString(), "utf8");
  }
  if (body instanceof FormData) {
    throw new TypeError(
      "@veilgate/node: FormData body is not supported — convert to Buffer or string first",
    );
  }
  // ReadableStream or Node AsyncIterable
  if (typeof (body as { getReader?: unknown }).getReader === "function") {
    const chunks: Uint8Array[] = [];
    const reader = (body as ReadableStream<Uint8Array>).getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
    const total = chunks.reduce((n, c) => n + c.length, 0);
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.length; }
    return merged;
  }
  throw new TypeError("@veilgate/node: unsupported body type");
}
