/**
 * @veilgate/node — server-side SDK
 *
 * For server-to-server calls to a VeilGate-protected API.
 *
 * Two modes:
 *   - Bearer: attach a static API token (Stripe/GitHub PAT model)
 *   - HMAC:   sign each request with a per-request signature
 *
 * Usage:
 *   import { bearerFetch, hmacFetch, signRequest } from "@veilgate/node";
 *
 *   // Bearer mode
 *   const apiFetch = bearerFetch("vg_live_abc123");
 *   const resp = await apiFetch("https://api.example.com/data");
 *
 *   // HMAC mode
 *   const apiFetch = hmacFetch({ clientId: "payments", secret: process.env.VG_SECRET! });
 *   const resp = await apiFetch("https://api.example.com/data");
 */

import { createHmac, timingSafeEqual, createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
