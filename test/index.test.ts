import { describe, it, expect, vi } from "vitest";
import {
  bearerFetch,
  hmacFetch,
  signRequest,
  signHeaders,
  verifySignature,
} from "../src/index";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type FetchCall = [RequestInfo | URL, RequestInit | undefined];

function makeFetchSpy(status = 200, body = {}): [typeof fetch, FetchCall[]] {
  const calls: FetchCall[] = [];
  const spy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push([input, init]);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
    } as Response;
  });
  return [spy as unknown as typeof fetch, calls];
}

// ---------------------------------------------------------------------------
// bearerFetch
// ---------------------------------------------------------------------------

describe("bearerFetch()", () => {
  it("attaches the bearer token as Authorization: Bearer <token>", async () => {
    const [spy, calls] = makeFetchSpy();
    const apiFetch = bearerFetch("my-secret-token", spy);
    await apiFetch("https://api.example.com/data");

    const [, init] = calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe("Bearer my-secret-token");
  });

  it("accepts options object for custom header and scheme", async () => {
    const [spy, calls] = makeFetchSpy();
    const apiFetch = bearerFetch(
      { token: "tok123", header: "X-Api-Key", scheme: "" },
      spy,
    );
    await apiFetch("https://api.example.com/data");

    const [, init] = calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get("x-api-key")).toBe("tok123");
    expect(headers.has("authorization")).toBe(false);
  });

  it("does not overwrite an existing token the caller set", async () => {
    const [spy, calls] = makeFetchSpy();
    const apiFetch = bearerFetch("sdk-token", spy);
    await apiFetch("https://api.example.com/data", {
      headers: { Authorization: "Bearer caller-token" },
    });

    const [, init] = calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe("Bearer caller-token");
  });

  it("passes through the response unmodified", async () => {
    const [spy] = makeFetchSpy(404, { error: "not found" });
    const apiFetch = bearerFetch("tok", spy);
    const resp = await apiFetch("https://api.example.com/missing");
    expect(resp.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// signRequest + verifySignature
// ---------------------------------------------------------------------------

describe("signRequest() / verifySignature()", () => {
  const secret = "test-secret-for-hmac";

  it("produces a t=…,v1=… signature", () => {
    const sig = signRequest(secret, "GET", "/api/data");
    expect(sig).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
  });

  it("round-trips: sign then verify", () => {
    const body = Buffer.from('{"amount":100}', "utf8");
    const sig = signRequest(secret, "POST", "/api/charge", body);
    expect(
      verifySignature(sig, secret, "POST", "/api/charge", body),
    ).toBe(true);
  });

  it("rejects tampered MAC", () => {
    const sig = signRequest(secret, "GET", "/api/data");
    const tampered = sig.replace(/v1=[0-9a-f]{4}/, "v1=0000");
    expect(verifySignature(tampered, secret, "GET", "/api/data")).toBe(false);
  });

  it("rejects wrong method", () => {
    const sig = signRequest(secret, "GET", "/api/data");
    expect(verifySignature(sig, secret, "POST", "/api/data")).toBe(false);
  });

  it("rejects wrong path", () => {
    const sig = signRequest(secret, "GET", "/api/data");
    expect(verifySignature(sig, secret, "GET", "/api/other")).toBe(false);
  });

  it("rejects wrong secret", () => {
    const sig = signRequest(secret, "GET", "/api/data");
    expect(verifySignature(sig, "wrong-secret", "GET", "/api/data")).toBe(false);
  });

  it("rejects expired timestamp (beyond replay window)", () => {
    const old = Math.floor(Date.now() / 1000) - 400;
    const sig = signRequest(secret, "GET", "/api/data", Buffer.alloc(0), old);
    expect(verifySignature(sig, secret, "GET", "/api/data", Buffer.alloc(0), { replayWindow: 300 })).toBe(false);
  });

  it("accepts timestamp within custom replay window", () => {
    const fresh = Math.floor(Date.now() / 1000) - 200;
    const sig = signRequest(secret, "GET", "/api/data", Buffer.alloc(0), fresh);
    expect(verifySignature(sig, secret, "GET", "/api/data", Buffer.alloc(0), { replayWindow: 300 })).toBe(true);
  });

  it("accepts string body same as Buffer body", () => {
    const bodyStr = '{"ok":true}';
    const bodyBuf = Buffer.from(bodyStr, "utf8");
    const ts = Math.floor(Date.now() / 1000);
    const sigStr = signRequest(secret, "POST", "/api", bodyStr, ts);
    const sigBuf = signRequest(secret, "POST", "/api", bodyBuf, ts);
    expect(sigStr).toBe(sigBuf);
  });
});

// ---------------------------------------------------------------------------
// signHeaders
// ---------------------------------------------------------------------------

describe("signHeaders()", () => {
  it("returns X-Veilgate-Signature and X-Veilgate-Client", () => {
    const hdrs = signHeaders(
      { clientId: "payments", secret: "my-secret" },
      "GET",
      "/api/data",
    );
    expect(hdrs["X-Veilgate-Signature"]).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(hdrs["X-Veilgate-Client"]).toBe("payments");
  });

  it("uses custom header names when provided", () => {
    const hdrs = signHeaders(
      {
        clientId: "svc",
        secret: "s3cr3t",
        signatureHeader: "X-Sig",
        clientHeader: "X-Client-Id",
      },
      "POST",
      "/charge",
    );
    expect("X-Sig" in hdrs).toBe(true);
    expect("X-Client-Id" in hdrs).toBe(true);
    expect("X-Veilgate-Signature" in hdrs).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// hmacFetch
// ---------------------------------------------------------------------------

describe("hmacFetch()", () => {
  const secret = "hmac-test-secret";
  const clientId = "test-service";

  it("attaches X-Veilgate-Signature and X-Veilgate-Client to requests", async () => {
    const [spy, calls] = makeFetchSpy();
    const apiFetch = hmacFetch({ clientId, secret }, spy);
    await apiFetch("https://api.example.com/api/data");

    const [, init] = calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get("x-veilgate-signature")).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(headers.get("x-veilgate-client")).toBe(clientId);
  });

  it("produces a verifiable signature for GET requests", async () => {
    let capturedHeaders: Headers | null = null;
    const spy = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers);
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch;

    const apiFetch = hmacFetch({ clientId, secret }, spy);
    await apiFetch("https://api.example.com/api/data?q=1");

    const sig = capturedHeaders!.get("x-veilgate-signature")!;
    expect(verifySignature(sig, secret, "GET", "/api/data?q=1")).toBe(true);
  });

  it("hashes the request body for POST requests", async () => {
    let capturedHeaders: Headers | null = null;
    const spy = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers);
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch;

    const body = JSON.stringify({ amount: 100 });
    const apiFetch = hmacFetch({ clientId, secret }, spy);
    await apiFetch("https://api.example.com/charge", {
      method: "POST",
      body,
      headers: { "Content-Type": "application/json" },
    });

    const sig = capturedHeaders!.get("x-veilgate-signature")!;
    expect(
      verifySignature(sig, secret, "POST", "/charge", Buffer.from(body)),
    ).toBe(true);
  });

  it("signs an empty body for GET requests", async () => {
    let capturedHeaders: Headers | null = null;
    const spy = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers);
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch;

    const apiFetch = hmacFetch({ clientId, secret }, spy);
    await apiFetch("https://api.example.com/items");

    const sig = capturedHeaders!.get("x-veilgate-signature")!;
    // Empty body hash is SHA-256 of empty string.
    expect(verifySignature(sig, secret, "GET", "/items", Buffer.alloc(0))).toBe(true);
  });
});
