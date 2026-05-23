# @veilgate/node

Node.js SDK for [VeilGate](https://github.com/C0oki3s/veilgate). Three responsibilities:

1. **Outgoing auth** — attach bearer tokens or HMAC-sign server-to-server requests.
2. **Decoy response headers** — inject tarpit breadcrumbs into your API's outgoing responses so agents probing the API via raw HTTP find bait paths instead of real endpoints.
3. **Signature verification** — validate inbound HMAC signatures in tests or custom middleware.

## Install

```bash
npm install @veilgate/node
```

Requires Node.js ≥ 18.

## Usage

### Bearer mode

```ts
import { bearerFetch } from "@veilgate/node";

const apiFetch = bearerFetch("vg_live_abc123");
const resp = await apiFetch("https://api.example.com/widgets");
```

Custom header or scheme:

```ts
const apiFetch = bearerFetch({ token: "abc123", header: "X-Api-Key", scheme: "" });
```

### HMAC mode

```ts
import { hmacFetch } from "@veilgate/node";

const apiFetch = hmacFetch({
  clientId: "payments",
  secret: process.env.VG_SECRET!,
});

const resp = await apiFetch("https://api.example.com/charge", {
  method: "POST",
  body: JSON.stringify({ amount: 100 }),
  headers: { "Content-Type": "application/json" },
});
```

### Decoy response middleware

Add tarpit breadcrumbs to every outgoing API response. Compatible with Express,
Fastify, and raw Node `http.Server` — anything with `res.setHeader()`.

```ts
import { decoyMiddleware } from "@veilgate/node";

// Express
const decoys = decoyMiddleware({ baseURL: "https://api.example.com" });
app.use(decoys);

// Runtime controls — no need to recreate the middleware
decoys.setEnabled(false);           // disable (e.g. internal health-check routes)
decoys.setEnabled(true);            // re-enable
decoys.update({ count: 5 });        // inject more paths per response
decoys.update({ baseURL: "https://new-api.example.com" }); // switch server (clears cache)
decoys.update({ paths: [          // static override — skips .well-known discovery
  { path: "/actuator/env", service: "spring-actuator" },
  { path: "/v1/secret/data/prod", service: "vault" },
]});
```

Agents probing the API will see response headers like:

```
Link: </actuator/env>; rel="help", </.env.local>; rel="related"
X-Api-Documentation: /swagger-ui.html
X-Debug-Endpoint: /api/internal/debug
```

### Low-level decoy helpers

```ts
import { fetchDecoyPaths, decoyResponseHeaders } from "@veilgate/node";

// Fetch tarpit.paths from .well-known (60 s cache)
const paths = await fetchDecoyPaths("https://api.example.com");

// Build a header map from any path list
const headers = decoyResponseHeaders(paths, { count: 3 });
// → { Link: "...", "X-Api-Documentation": "...", "X-Debug-Endpoint": "..." }

// Attach to a raw Node response
for (const [name, value] of Object.entries(headers)) {
  res.setHeader(name, value);
}
```

## API

### `bearerFetch(tokenOrOpts, fetchImpl?)`

Returns a `fetch`-compatible function with a static bearer token attached.
Does not override an existing `Authorization` header set by the caller.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token` | `string` | — | Token value |
| `header` | `string` | `"Authorization"` | Header name |
| `scheme` | `string` | `"Bearer"` | Scheme prefix. Pass `""` for raw-token mode |

### `hmacFetch(opts, fetchImpl?)`

Returns a `fetch`-compatible function that signs every request with HMAC-SHA256.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `clientId` | `string` | — | Sent in `X-Veilgate-Client` |
| `secret` | `string` | — | Shared HMAC secret |
| `signatureHeader` | `string` | `"X-Veilgate-Signature"` | Override signature header |
| `clientHeader` | `string` | `"X-Veilgate-Client"` | Override client-id header |
| `replayWindow` | `number` | `300` | Replay protection window in seconds |

### `fetchDecoyPaths(baseURL?, fetchImpl?)`

Fetches `/__veilgate/.well-known` and returns the `tarpit.paths` array. Results
are cached for 60 seconds matching the server's `Cache-Control: max-age=60`.
Returns an empty array on any error.

### `decoyResponseHeaders(paths, opts?)`

Pure function. Builds a `Record<string, string>` of HTTP response headers from
a path list. Headers produced:

| Header | Condition |
|--------|-----------|
| `Link` | Always (when `linkHeader !== false`). RFC 8288 `rel` types: `help`, `related`, `about`, `describedby` |
| `X-Api-Documentation` | When a path matching `openapi`/`swagger` is in the picked set |
| `X-Debug-Endpoint` | When a path matching `debug`/`internal` is in the picked set |

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `count` | `number` | `3` | Paths to inject |
| `linkHeader` | `boolean` | `true` | Emit `Link` header |
| `serviceHeaders` | `boolean` | `true` | Emit `X-Api-Documentation` / `X-Debug-Endpoint` |

### `decoyMiddleware(opts?)`

Returns a `DecoyMiddlewareFn` — callable as a standard middleware and extended
with runtime controls.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `baseURL` | `string` | `""` | VeilGate server for `.well-known` discovery |
| `paths` | `TarpitPathEntry[]` | — | Static override; skips discovery |
| `count` | `number` | `3` | Paths per response |
| `linkHeader` | `boolean` | `true` | Emit `Link` header |
| `serviceHeaders` | `boolean` | `true` | Emit service-hinting headers |
| `fetchImpl` | `typeof fetch` | `globalThis.fetch` | Override for tests |

**Runtime methods on the returned function:**

| Method | Description |
|--------|-------------|
| `.setEnabled(boolean)` | Enable or disable header injection without recreating the middleware |
| `.update(Partial<DecoyOptions>)` | Merge new options; clears discovery cache when `baseURL` or `paths` changes |

### `signRequest(secret, method, path, body?, timestamp?)`

Compute a `t=<ts>,v1=<mac>` signature string directly.

### `signHeaders(opts, method, path, body?, timestamp?)`

Returns a `{ [header]: value }` object ready to spread into your request headers.

### `verifySignature(signature, secret, method, path, body?, opts?)`

Verify an inbound HMAC signature. Returns `true` only when the MAC is valid **and** the timestamp is within the replay window. Uses `timingSafeEqual` internally.

## Signature Format

```
Canonical: <unix-ts>.<METHOD>.<path+query>.<hex(sha256(body))>
Signature: t=<ts>,v1=<hex(HMAC-SHA256(secret, canonical))>
```

## License

MIT
