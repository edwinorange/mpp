import {
  Credential,
  Method,
  Constants as MppConstants,
  Receipt,
  z,
} from "mppx";
import * as Attestation from "mppx/attestation";
import * as Tap from "mppx/attestation/tap";
import * as WebBotAuth from "mppx/attestation/web-bot-auth";
import { Fetch } from "mppx/client";
import { Mppx } from "mppx/server";
import { describe, expect, it, vi } from "vitest";
import {
  createRedisNonceStore,
  createTrustedAgentPaymentHandler,
  TAP_REGISTRY_URL,
  WEB_BOT_AUTH_DIRECTORY_ORIGIN,
  WEB_BOT_AUTH_DIRECTORY_URL,
} from "./trusted-agent-payment.server";

const ENDPOINT = "https://mpp.dev/api/ping/paid/agent";

const method = Method.from({
  intent: "charge",
  name: "test",
  schema: {
    credential: { payload: z.object({ token: z.string() }) },
    request: z.object({
      amount: z.string(),
      currency: z.string(),
      recipient: z.string(),
    }),
  },
});

const clientMethod = Method.toClient(method, {
  async createCredential({ challenge }) {
    return Credential.serialize({
      challenge,
      payload: { token: "paid" },
    });
  },
});

const serverMethod = Method.toServer(method, {
  async verify({ credential }) {
    if (credential.payload.token !== "paid") {
      throw new Error("Payment credential is invalid.");
    }
    return Receipt.from({
      method: "test",
      reference: "test-payment",
      status: "success",
      timestamp: new Date().toISOString(),
    });
  },
});

describe("trusted agent payment boundary", () => {
  it.each([
    { name: "neither signature", tap: false, webBotAuth: false },
    { name: "Web Bot Auth only", tap: false, webBotAuth: "trusted" },
    { name: "TAP only", tap: "trusted", webBotAuth: false },
  ] as const)("rejects $name before payment", async (options) => {
    const setup = await createSetup();
    const request = await signRequest(setup, options);

    const response = await setup.handler(request);

    expect(response.status).toBe(403);
    expect(setup.paymentInvocations).toHaveLength(0);
  });

  it("rejects TAP browse intent before payment", async () => {
    const setup = await createSetup();
    const request = await signRequest(setup, {
      intent: Tap.Constants.intents.browse,
      tap: "trusted",
      webBotAuth: "trusted",
    });

    const response = await setup.handler(request);

    expect(response.status).toBe(403);
    expect(setup.paymentInvocations).toHaveLength(0);
  });

  it.each([
    {
      name: "unregistered Web Bot Auth key",
      tap: "trusted",
      webBotAuth: "unknown",
    },
    { name: "unregistered TAP key", tap: "unknown", webBotAuth: "trusted" },
  ] as const)("rejects an $name before payment", async (options) => {
    const setup = await createSetup();
    const request = await signRequest(setup, options);

    const response = await setup.handler(request);

    expect(response.status).toBe(401);
    expect(setup.paymentInvocations).toHaveLength(0);
  });

  it("rejects an untrusted Signature-Agent origin without fetching it", async () => {
    const setup = await createSetup();
    const request = await Attestation.Client.composeSigners(
      WebBotAuth.Client.signer({
        key: setup.webBotAuthKeys.privateKey,
        keyId: setup.webBotAuthKeyId,
        signatureAgent: "https://untrusted-agent.example",
      }),
      Tap.Client.signer({
        intent: Tap.Constants.intents.payment,
        key: setup.tapKeys.privateKey,
        keyId: setup.tapKeyId,
      }),
    ).sign(new Request(ENDPOINT));

    const response = await setup.handler(request);

    expect(response.status).toBe(401);
    expect(setup.paymentInvocations).toHaveLength(0);
    expect(setup.registryFetch).not.toHaveBeenCalledWith(
      WEB_BOT_AUTH_DIRECTORY_URL,
      expect.anything(),
    );
    expect(
      setup.registryFetch.mock.calls.map(([input]) => String(input)),
    ).toEqual([TAP_REGISTRY_URL]);
  });

  it("rejects a tampered request signature before payment", async () => {
    const setup = await createSetup();
    const signed = await signRequest(setup, {
      tap: "trusted",
      webBotAuth: "trusted",
    });
    const headers = new Headers(signed.headers);
    headers.set(
      Attestation.Headers.signature,
      tamperByteSequence(headers.get(Attestation.Headers.signature) ?? ""),
    );

    const response = await setup.handler(new Request(signed, { headers }));

    expect(response.status).toBe(401);
    expect(setup.paymentInvocations).toHaveLength(0);
  });

  it("rejects valid signatures with different request-attempt nonces", async () => {
    const setup = await createSetup();
    const request = await signRequest(
      setup,
      { tap: "trusted", webBotAuth: "trusted" },
      false,
    );

    const response = await setup.handler(request);

    expect(response.status).toBe(403);
    expect(setup.paymentInvocations).toHaveLength(0);
  });

  it("lets valid registered signatures reach the payment handler", async () => {
    const setup = await createSetup();
    const request = await signRequest(setup, {
      tap: "trusted",
      webBotAuth: "trusted",
    });

    const response = await setup.handler(request);

    expect(response.status).toBe(402);
    expect(response.headers.get("www-authenticate")).toMatch(/^Payment /);
    expect(setup.paymentInvocations).toHaveLength(1);
    expect(setup.registryFetch).toHaveBeenCalledTimes(2);
    expect(setup.registryFetch).toHaveBeenCalledWith(
      TAP_REGISTRY_URL,
      expect.objectContaining({ redirect: "error" }),
    );
    expect(setup.registryFetch).toHaveBeenCalledWith(
      WEB_BOT_AUTH_DIRECTORY_URL,
      expect.objectContaining({ redirect: "error" }),
    );
  });

  it("rejects replay before issuing another payment challenge", async () => {
    const setup = await createSetup();
    const request = await signRequest(setup, {
      tap: "trusted",
      webBotAuth: "trusted",
    });

    expect((await setup.handler(request.clone())).status).toBe(402);
    expect((await setup.handler(request.clone())).status).toBe(401);
    expect(setup.paymentInvocations).toHaveLength(1);
  });

  it("completes an MPP paid retry with fresh composed signatures", async () => {
    const setup = await createSetup();
    const signer = Attestation.Client.composeSigners(
      WebBotAuth.Client.signer({
        key: setup.webBotAuthKeys.privateKey,
        keyId: setup.webBotAuthKeyId,
        signatureAgent: WEB_BOT_AUTH_DIRECTORY_ORIGIN,
      }),
      Tap.Client.signer({
        intent: Tap.Constants.intents.payment,
        key: setup.tapKeys.privateKey,
        keyId: setup.tapKeyId,
      }),
    );
    const fetch = Fetch.from({
      fetch: Attestation.Client.wrapFetch(
        async (input, init) => setup.handler(new Request(input, init)),
        signer,
      ),
      methods: [clientMethod],
    });

    const response = await fetch(ENDPOINT);

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("trusted and paid");
    expect(
      response.headers.get(MppConstants.Headers.paymentReceipt),
    ).toBeTruthy();
    expect(setup.paymentInvocations).toHaveLength(2);

    const attemptNonces = setup.paymentInvocations.map(signatureNonces);
    expect(attemptNonces).toHaveLength(2);
    for (const nonces of attemptNonces) {
      expect(nonces).toHaveLength(2);
      expect(new Set(nonces).size).toBe(1);
    }
    expect(attemptNonces[0]?.[0]).not.toBe(attemptNonces[1]?.[0]);
  });

  it.each([
    { failure: "digest", name: "content digest" },
    { failure: "expired", name: "expired directory response signature" },
    { failure: "signature", name: "directory response signature" },
  ] as const)("ignores WBA keys with an invalid $name", async ({ failure }) => {
    const setup = await createSetup({ directoryFailure: failure });
    const request = await signRequest(setup, {
      tap: "trusted",
      webBotAuth: "trusted",
    });

    const response = await setup.handler(request);

    expect(response.status).toBe(401);
    expect(setup.paymentInvocations).toHaveLength(0);
  });

  it("ignores WBA directory keys whose kid is not their JWK thumbprint", async () => {
    const setup = await createSetup({ invalidDirectoryThumbprint: true });
    const request = await signRequest(setup, {
      tap: "trusted",
      webBotAuth: "trusted",
    });

    const response = await setup.handler(request);

    expect(response.status).toBe(401);
    expect(setup.paymentInvocations).toHaveLength(0);
  });
});

describe("Redis replay store", () => {
  it("uses one atomic SET NX with the signature expiry", async () => {
    const set = vi.fn().mockResolvedValueOnce("OK").mockResolvedValueOnce(null);
    const store = createRedisNonceStore({ set });
    const expires = Date.now() + 30_000;

    expect(await store.consume("tap:key:nonce", expires)).toBe(false);
    expect(await store.consume("tap:key:nonce", expires)).toBe(true);
    expect(set).toHaveBeenCalledTimes(2);
    expect(set).toHaveBeenCalledWith(
      "mpp:attestation:nonce:tap:key:nonce",
      "1",
      expect.objectContaining({
        nx: true,
        px: expect.any(Number),
      }),
    );
  });
});

type Setup = Awaited<ReturnType<typeof createSetup>>;

async function createSetup({
  directoryFailure,
  invalidDirectoryThumbprint = false,
}: {
  directoryFailure?: "digest" | "expired" | "signature";
  invalidDirectoryThumbprint?: boolean;
} = {}) {
  const tapKeys = await keyPair();
  const unknownTapKeys = await keyPair();
  const webBotAuthKeys = await keyPair();
  const unknownWebBotAuthKeys = await keyPair();
  const tapKeyId = "trusted-tap-key";
  const webBotAuthKeyId = await jwkThumbprint(webBotAuthKeys.publicKey);
  const unknownWebBotAuthKeyId = await jwkThumbprint(
    unknownWebBotAuthKeys.publicKey,
  );
  const tapJwk = await publicJwk(tapKeys.publicKey, tapKeyId, true);
  const webBotAuthJwk = await publicJwk(
    webBotAuthKeys.publicKey,
    invalidDirectoryThumbprint ? "not-a-jwk-thumbprint" : webBotAuthKeyId,
    false,
  );
  const directoryResponse = await signedDirectoryResponse({
    failure: directoryFailure,
    key: webBotAuthKeys.privateKey,
    publicJwk: webBotAuthJwk,
  });
  const registryFetch = vi.fn(
    async (input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url === TAP_REGISTRY_URL) {
        return Response.json(
          { keys: [tapJwk] },
          {
            headers: { "content-type": "application/jwk-set+json" },
          },
        );
      }
      if (url === WEB_BOT_AUTH_DIRECTORY_URL) {
        return directoryResponse.clone();
      }
      throw new Error(`Unexpected registry URL: ${url}`);
    },
  );
  const consumed = new Set<string>();
  const nonceStore = {
    consume(value: string) {
      if (consumed.has(value)) return true;
      consumed.add(value);
      return false;
    },
  };
  const payments = Mppx.create({
    methods: [serverMethod],
    realm: "mpp.dev",
    secretKey: "test-secret-key-test-secret-key-32",
  });
  const charge = payments.charge({
    amount: "1",
    currency: "USD",
    expires: new Date(Date.now() + 60_000).toISOString(),
    recipient: "merchant",
  });
  const paymentInvocations: string[] = [];
  const handler = createTrustedAgentPaymentHandler(
    async (request) => {
      paymentInvocations.push(
        request.headers.get(Attestation.Headers.signatureInput) ?? "",
      );
      const result = await charge(request);
      if (result.status === 402) return result.challenge;
      return result.withReceipt(new Response("trusted and paid"));
    },
    { nonceStore, registryFetch },
  );

  return {
    handler,
    paymentInvocations,
    registryFetch,
    tapKeyId,
    tapKeys,
    unknownTapKeys,
    unknownWebBotAuthKeyId,
    unknownWebBotAuthKeys,
    webBotAuthKeyId,
    webBotAuthKeys,
  };
}

async function signRequest(
  setup: Setup,
  {
    intent = Tap.Constants.intents.payment,
    tap,
    webBotAuth,
  }: {
    intent?: (typeof Tap.Constants.intents)[keyof typeof Tap.Constants.intents];
    tap: "trusted" | "unknown" | false;
    webBotAuth: "trusted" | "unknown" | false;
  },
  shareContext = true,
) {
  const signers: Attestation.Signer[] = [];
  if (webBotAuth) {
    const trusted = webBotAuth === "trusted";
    signers.push(
      WebBotAuth.Client.signer({
        key: trusted
          ? setup.webBotAuthKeys.privateKey
          : setup.unknownWebBotAuthKeys.privateKey,
        keyId: trusted ? setup.webBotAuthKeyId : setup.unknownWebBotAuthKeyId,
        signatureAgent: WEB_BOT_AUTH_DIRECTORY_ORIGIN,
      }),
    );
  }
  if (tap) {
    const trusted = tap === "trusted";
    signers.push(
      Tap.Client.signer({
        intent,
        key: trusted
          ? setup.tapKeys.privateKey
          : setup.unknownTapKeys.privateKey,
        keyId: trusted ? setup.tapKeyId : "unknown-tap-key",
      }),
    );
  }

  let request = new Request(ENDPOINT);
  if (shareContext && signers.length > 1) {
    return Attestation.Client.composeSigners(
      signers[0]!,
      ...signers.slice(1),
    ).sign(request);
  }
  for (const signer of signers) request = await signer.sign(request);
  return request;
}

async function signedDirectoryResponse({
  failure,
  key,
  publicJwk,
}: {
  failure?: "digest" | "expired" | "signature";
  key: CryptoKey;
  publicJwk: JsonWebKey & { kid: string };
}) {
  const body = JSON.stringify({ keys: [publicJwk] }, null, 2);
  const bytes = new TextEncoder().encode(body);
  const digestBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes),
  );
  const contentDigest = `sha-256=:${toBase64(digestBytes)}:`;
  const created = Math.floor(Date.now() / 1_000) - 1;
  const expires = failure === "expired" ? created : created + 3_600;
  const parameters =
    `("@authority";req "content-digest");created=${created};expires=${expires}` +
    `;keyid="${publicJwk.kid}";alg="ed25519";tag="http-message-signatures-directory"`;
  const signatureBase = [
    `"@authority";req: ${new URL(WEB_BOT_AUTH_DIRECTORY_URL).host}`,
    `"content-digest": ${contentDigest}`,
    `"@signature-params": ${parameters}`,
  ].join("\n");
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "Ed25519",
      key,
      new TextEncoder().encode(signatureBase),
    ),
  );
  if (failure === "signature") signature[0] ^= 1;

  return new Response(body, {
    headers: {
      "content-digest":
        failure === "digest"
          ? "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
          : contentDigest,
      "content-type": "application/http-message-signatures-directory+json",
      signature: `directory=:${toBase64(signature)}:`,
      "signature-input": `directory=${parameters}`,
    },
  });
}

async function keyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

async function publicJwk(
  key: CryptoKey,
  keyId: string,
  includeAlgorithm: boolean,
): Promise<JsonWebKey & { kid: string }> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return {
    ...(includeAlgorithm
      ? {
          alg: "EdDSA",
          key_ops: ["verify"],
        }
      : {}),
    crv: jwk.crv,
    ext: true,
    kid: keyId,
    kty: jwk.kty,
    use: "sig",
    x: jwk.x,
  };
}

async function jwkThumbprint(key: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  });
  return toBase64Url(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(canonical),
      ),
    ),
  );
}

function signatureNonces(signatureInput: string) {
  return [...signatureInput.matchAll(/nonce="([^"]+)"/g)].map(
    (match) => match[1],
  );
}

function tamperByteSequence(value: string) {
  return value.replace(/:([A-Za-z0-9+/])/, (_match, character: string) =>
    character === "A" ? ":B" : ":A",
  );
}

function toBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function toBase64Url(bytes: Uint8Array) {
  return toBase64(bytes)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}
