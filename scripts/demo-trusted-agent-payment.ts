/**
 * Runs the laptop side of the TAP + Web Bot Auth + Tempo payment demo.
 *
 * Private keys are loaded only from environment variables or local file paths.
 * This script never writes them or includes them in its output.
 */
import { readFile } from "node:fs/promises";
import { Constants as MppConstants } from "mppx";
import * as Attestation from "mppx/attestation";
import * as Tap from "mppx/attestation/tap";
import * as WebBotAuth from "mppx/attestation/web-bot-auth";
import { Fetch, tempo } from "mppx/client";
import { privateKeyToAccount } from "viem/accounts";

const signatureAgent = "https://agents.tempo.xyz";
const url =
  process.env.DEMO_TRUSTED_AGENT_URL ?? "https://mpp.dev/api/ping/paid/agent";

const webBotAuth = await loadEd25519Key(
  requiredEnvironment("DEMO_WBA_PRIVATE_JWK_PATH"),
  true,
);
const tap = await loadEd25519Key(
  requiredEnvironment("DEMO_TAP_PRIVATE_JWK_PATH"),
  false,
);
const account = privateKeyToAccount(await loadTempoPrivateKey());
const signer = Attestation.Client.composeSigners(
  WebBotAuth.Client.signer({
    key: webBotAuth.key,
    keyId: webBotAuth.keyId,
    signatureAgent,
  }),
  Tap.Client.signer({
    intent: Tap.Constants.intents.payment,
    key: tap.key,
    keyId: tap.keyId,
  }),
);
const attempts: Attempt[] = [];
const observedFetch: typeof globalThis.fetch = async (input, init) => {
  const request = new Request(input, init);
  const signatureInput =
    request.headers.get(Attestation.Headers.signatureInput) ?? "";
  const response = await globalThis.fetch(request);
  const nonces = [...signatureInput.matchAll(/nonce="([^"]+)"/g)].map(
    (match) => match[1]!,
  );
  attempts.push({
    paid:
      request.headers
        .get(MppConstants.Headers.authorization)
        ?.startsWith("Payment ") ?? false,
    nonces,
    status: response.status,
  });
  return response;
};
const fetch = Fetch.from({
  fetch: Attestation.Client.wrapFetch(observedFetch, signer),
  methods: [tempo.charge({ account })],
});

console.log(`Agent account: ${account.address}`);
console.log(`WBA key: ${webBotAuth.keyId}`);
console.log(`TAP key: ${tap.keyId}`);
console.log(`Requesting: ${url}`);

const response = await fetch(url);
for (const [index, attempt] of attempts.entries()) {
  const [webBotAuthNonce, tapNonce] = attempt.nonces;
  console.log(
    [
      `Attempt ${index + 1}: HTTP ${attempt.status}`,
      attempt.paid ? "Payment Credential attached" : "no Payment Credential",
      `WBA nonce ${webBotAuthNonce ?? "(missing)"}`,
      `TAP nonce ${tapNonce ?? "(missing)"}`,
      webBotAuthNonce && webBotAuthNonce === tapNonce
        ? "shared request nonce"
        : "nonce mismatch",
    ].join(" | "),
  );
}

const receipt = response.headers.get(MppConstants.Headers.paymentReceipt);
console.log(`Final response: HTTP ${response.status}`);
console.log(`Payment-Receipt: ${receipt ?? "(missing)"}`);
console.log(`Body: ${await response.text()}`);

if (
  attempts.length !== 2 ||
  attempts[0]?.status !== 402 ||
  !attempts[1]?.paid ||
  !response.ok ||
  !receipt
) {
  process.exitCode = 1;
}

type Attempt = {
  nonces: string[];
  paid: boolean;
  status: number;
};

async function loadEd25519Key(path: string, requireThumbprint: boolean) {
  const document = await readJson(path);
  if (!isRecord(document)) {
    throw new Error(`${path} must contain a JSON object.`);
  }
  const privateKeyJwk = isRecord(document.privateKeyJwk)
    ? document.privateKeyJwk
    : document;
  if (
    privateKeyJwk.kty !== "OKP" ||
    privateKeyJwk.crv !== "Ed25519" ||
    typeof privateKeyJwk.d !== "string" ||
    typeof privateKeyJwk.x !== "string"
  ) {
    throw new Error(`${path} must contain an Ed25519 private JWK.`);
  }

  const thumbprint = await jwkThumbprint(privateKeyJwk);
  const configuredKeyId =
    typeof document.keyId === "string"
      ? document.keyId
      : typeof privateKeyJwk.kid === "string"
        ? privateKeyJwk.kid
        : undefined;
  if (requireThumbprint && configuredKeyId && configuredKeyId !== thumbprint) {
    throw new Error(
      `${path} keyId must equal its RFC 7638 JWK thumbprint for Web Bot Auth.`,
    );
  }
  const keyId = requireThumbprint
    ? thumbprint
    : (configuredKeyId ?? thumbprint);
  const key = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  return { key, keyId };
}

async function loadTempoPrivateKey(): Promise<`0x${string}`> {
  const direct = process.env.DEMO_TEMPO_PRIVATE_KEY?.trim();
  const path = process.env.DEMO_TEMPO_PRIVATE_KEY_PATH?.trim();
  let value: unknown = direct;
  if (!value && path) {
    const document = await readJson(path);
    value = isRecord(document) ? document.privateKey : document;
  }
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(
      "Set DEMO_TEMPO_PRIVATE_KEY or DEMO_TEMPO_PRIVATE_KEY_PATH to a funded Tempo private key.",
    );
  }
  return value as `0x${string}`;
}

async function jwkThumbprint(jwk: Record<string, unknown>) {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  });
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)),
  );
  return Buffer.from(digest).toString("base64url");
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch (error) {
    throw new Error(`Could not read JSON from ${path}.`, { cause: error });
  }
}

function requiredEnvironment(name: string) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
