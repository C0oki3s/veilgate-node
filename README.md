# @veilgate/node

Node.js SDK for [VeilGate](https://github.com/C0oki3s/veilgate). Attach static bearer tokens or HMAC-sign every server-to-server request with a single wrapper around `fetch`.

## Install

```bash
npm install @veilgate/node
```

Requires Node.js ≥ 18.

## Usage

### Bearer mode

Attach a static API token to every request — the Stripe/GitHub PAT model.

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

Sign each request with a per-request HMAC-SHA256 signature.

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

## API

### `bearerFetch(tokenOrOpts, fetchImpl?)`

Returns a `fetch`-compatible function with a static bearer token attached.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token` | `string` | — | Token value |
| `header` | `string` | `"Authorization"` | Header name |
| `scheme` | `string` | `"Bearer"` | Scheme prefix. Pass `""` for raw-token mode |

### `hmacFetch(opts, fetchImpl?)`

Returns a `fetch`-compatible function that signs every request.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `clientId` | `string` | — | Sent in `X-Veilgate-Client` |
| `secret` | `string` | — | Shared HMAC secret |
| `signatureHeader` | `string` | `"X-Veilgate-Signature"` | Override signature header name |
| `clientHeader` | `string` | `"X-Veilgate-Client"` | Override client-id header name |
| `replayWindow` | `number` | `300` | Replay protection window in seconds |

### `signRequest(secret, method, path, body?, timestamp?)`

Compute a `t=<ts>,v1=<mac>` signature string directly.

### `signHeaders(opts, method, path, body?, timestamp?)`

Returns a `{ [header]: value }` object ready to spread into your request headers.

### `verifySignature(signature, secret, method, path, body?, opts?)`

Verify an inbound signature. Returns `true` only when the MAC is valid **and** the timestamp is within the replay window. Uses `timingSafeEqual` internally.

## Signature Format

```
Canonical: <unix-ts>.<METHOD>.<path+query>.<hex(sha256(body))>
Signature: t=<ts>,v1=<hex(HMAC-SHA256(secret, canonical))>
```

## License

MIT
