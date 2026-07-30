import { Redis } from "@upstash/redis";
import * as Attestation from "mppx/attestation";
import * as Tap from "mppx/attestation/tap";
import * as WebBotAuth from "mppx/attestation/web-bot-auth";
import type { Dictionary, InnerList, Item } from "structured-headers";
import {
  isInnerList,
  parseDictionary,
  serializeInnerList,
  serializeItem,
} from "structured-headers";

export const TAP_REGISTRY_URL =
  "https://tap-registry-demo.vercel.app/.well-known/jwks";
export const WEB_BOT_AUTH_DIRECTORY_ORIGIN = "https://agents.tempo.xyz";
export const WEB_BOT_AUTH_DIRECTORY_URL =
  "https://agents.tempo.xyz/.well-known/http-message-signatures-directory";

const REGISTRY_REQUEST_TIMEOUT_MS = 5_000;
const TAP_KEY_CACHE_MS = 60 * 60 * 1_000;
const WEB_BOT_AUTH_KEY_CACHE_MS = 5 * 60 * 1_000;
const WEB_BOT_AUTH_DIRECTORY_SIGNATURE_TAG =
  "http-message-signatures-directory";

type KeyResolver = (parameters: {
  keyId: string;
  request: Request;
}) => CryptoKey | Promise<CryptoKey | undefined> | undefined;

type NonceStore = {
  consume(nonce: string, expires: number): boolean | Promise<boolean>;
};

type RedisSetClient = {
  set(
    key: string,
    value: string,
    options: { nx: true; px: number },
  ): Promise<string | null>;
};

type RequestHandler = (request: Request) => Promise<Response> | Response;

type TrustedAgentPaymentConfig = {
  nonceStore: NonceStore;
  registryFetch?: typeof globalThis.fetch;
};

/**
 * Requires registered Web Bot Auth identity and TAP payment intent before
 * invoking a payment handler.
 */
export function createTrustedAgentPaymentHandler(
  handler: RequestHandler,
  { nonceStore, registryFetch = globalThis.fetch }: TrustedAgentPaymentConfig,
): RequestHandler {
  const resolveTapKey = createCachedKeyResolver({
    cacheMs: TAP_KEY_CACHE_MS,
    load: () => fetchJwkSet(registryFetch, TAP_REGISTRY_URL),
  });
  const resolveWebBotAuthKey = createCachedKeyResolver({
    cacheMs: WEB_BOT_AUTH_KEY_CACHE_MS,
    load: () => fetchWebBotAuthDirectory(registryFetch),
  });

  return Attestation.Server.middleware(handler, {
    policy({ evidence }) {
      const tap = evidence.find(
        (entry): entry is Tap.Evidence =>
          entry.protocol === Tap.Constants.protocol,
      );
      const webBotAuth = evidence.find(
        (entry): entry is WebBotAuth.Evidence =>
          entry.protocol === WebBotAuth.Constants.protocol,
      );

      if (
        !tap ||
        tap.value.intent !== Tap.Constants.intents.payment ||
        !webBotAuth ||
        webBotAuth.value.signatureAgent !== WEB_BOT_AUTH_DIRECTORY_ORIGIN
      ) {
        return {
          allow: false,
          reason:
            "Registered Web Bot Auth identity and TAP payment intent are required.",
        };
      }

      if (tap.value.nonce !== webBotAuth.value.nonce) {
        return {
          allow: false,
          reason: "Attestation signature nonces must match.",
        };
      }

      return { allow: true };
    },
    verifiers: {
      [Tap.Constants.protocol]: Tap.Server.verifier({
        keyResolver: resolveTapKey,
        nonceStore,
      }),
      [WebBotAuth.Constants.protocol]: WebBotAuth.Server.verifier({
        keyResolver({ keyId, request, signatureAgent }) {
          if (signatureAgent !== WEB_BOT_AUTH_DIRECTORY_ORIGIN) {
            return undefined;
          }
          return resolveWebBotAuthKey({ keyId, request });
        },
        nonceStore,
      }),
    },
  });
}

/** Creates an atomic replay store using Redis SET NX with nonce expiry. */
export function createRedisNonceStore(redis: RedisSetClient): NonceStore {
  return {
    async consume(nonce, expires) {
      const ttl = Math.max(1, expires - Date.now());
      const result = await redis.set(`mpp:attestation:nonce:${nonce}`, "1", {
        nx: true,
        px: ttl,
      });
      return result === null;
    },
  };
}

/**
 * Resolves the production replay store, failing closed when Redis credentials
 * are absent outside local development and tests.
 */
export function createEnvironmentNonceStore(): NonceStore {
  const token = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
  const url = process.env.UPSTASH_REDIS_REST_URL?.trim();
  if (token && url) {
    return createRedisNonceStore(new Redis({ token, url }));
  }

  if (import.meta.env.DEV || process.env.NODE_ENV === "test") {
    return createMemoryNonceStore();
  }

  return {
    consume() {
      throw new Error(
        "UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are required for attestation replay protection.",
      );
    },
  };
}

function createCachedKeyResolver({
  cacheMs,
  load,
}: {
  cacheMs: number;
  load: () => Promise<ReadonlyMap<string, CryptoKey>>;
}): KeyResolver {
  let cache:
    | { expiresAt: number; keys: ReadonlyMap<string, CryptoKey> }
    | undefined;
  let refresh: Promise<ReadonlyMap<string, CryptoKey>> | undefined;

  return async ({ keyId }) => {
    if (cache && cache.expiresAt > Date.now()) {
      return cache.keys.get(keyId);
    }

    refresh ??= load().then((keys) => {
      cache = { expiresAt: Date.now() + cacheMs, keys };
      return keys;
    });

    try {
      return (await refresh).get(keyId);
    } finally {
      refresh = undefined;
    }
  };
}

async function fetchJwkSet(
  fetch: typeof globalThis.fetch,
  url: string,
): Promise<ReadonlyMap<string, CryptoKey>> {
  const { body } = await fetchRegistry(fetch, url);
  return importJwkSet(parseJwkSet(body));
}

async function fetchWebBotAuthDirectory(
  fetch: typeof globalThis.fetch,
): Promise<ReadonlyMap<string, CryptoKey>> {
  const { body, response } = await fetchRegistry(
    fetch,
    WEB_BOT_AUTH_DIRECTORY_URL,
  );
  if (
    response.headers
      .get("content-type")
      ?.split(";", 1)[0]
      ?.trim()
      .toLowerCase() !== "application/http-message-signatures-directory+json"
  ) {
    throw new Error(
      "Web Bot Auth directory returned an unexpected content type.",
    );
  }

  const contentDigest = response.headers.get("content-digest");
  if (!contentDigest || !(await verifyContentDigest(body, contentDigest))) {
    throw new Error("Web Bot Auth directory content digest is invalid.");
  }

  const inputs = parseHeaderDictionary(response.headers, "signature-input");
  const signatures = parseHeaderDictionary(response.headers, "signature");
  const values = parseJwkSet(body);
  const keys = new Map<string, CryptoKey>();
  for (const value of values) {
    if (!isPublicEd25519Jwk(value)) continue;
    if ((await jwkThumbprint(value)) !== value.kid) continue;
    if (keys.has(value.kid)) {
      throw new Error(
        `Web Bot Auth directory returned duplicate kid "${value.kid}".`,
      );
    }

    const key = await importVerificationKey(value);
    if (
      await hasValidDirectorySignature({
        contentDigest,
        inputs,
        key,
        keyId: value.kid,
        signatures,
      })
    ) {
      keys.set(value.kid, key);
    }
  }

  if (keys.size === 0) {
    throw new Error(
      "Web Bot Auth directory contained no keys with a valid directory signature.",
    );
  }
  return keys;
}

async function fetchRegistry(
  fetch: typeof globalThis.fetch,
  url: string,
): Promise<{ body: Uint8Array; response: Response }> {
  const response = await fetch(url, {
    cache: "no-store",
    headers: {
      accept:
        "application/http-message-signatures-directory+json, application/jwk-set+json, application/json",
    },
    redirect: "error",
    signal: AbortSignal.timeout(REGISTRY_REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`Trusted key registry returned HTTP ${response.status}.`);
  }
  if (response.url && response.url !== new URL(url).href) {
    throw new Error(
      "Trusted key registry returned a response from another URL.",
    );
  }
  return {
    body: new Uint8Array(await response.arrayBuffer()),
    response,
  };
}

function parseJwkSet(body: Uint8Array): unknown[] {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new Error("Trusted key registry returned invalid JSON.");
  }
  if (
    !isRecord(value) ||
    !Array.isArray(value.keys) ||
    value.keys.length === 0
  ) {
    throw new Error("Trusted key registry returned an invalid JWK Set.");
  }
  return value.keys;
}

async function importJwkSet(
  values: readonly unknown[],
): Promise<ReadonlyMap<string, CryptoKey>> {
  const keys = new Map<string, CryptoKey>();
  for (const value of values) {
    if (!isPublicEd25519Jwk(value)) continue;
    if (keys.has(value.kid)) {
      throw new Error(
        `Trusted key registry returned duplicate kid "${value.kid}".`,
      );
    }
    keys.set(value.kid, await importVerificationKey(value));
  }
  if (keys.size === 0) {
    throw new Error("Trusted key registry returned no supported Ed25519 keys.");
  }
  return keys;
}

async function hasValidDirectorySignature({
  contentDigest,
  inputs,
  key,
  keyId,
  signatures,
}: {
  contentDigest: string;
  inputs: Dictionary;
  key: CryptoKey;
  keyId: string;
  signatures: Dictionary;
}): Promise<boolean> {
  const now = Math.floor(Date.now() / 1_000);
  for (const [label, value] of inputs) {
    if (!isDirectorySignatureInput(value, keyId, now)) continue;
    const signature = signatures.get(label);
    if (
      !signature ||
      isInnerList(signature) ||
      !(signature[0] instanceof ArrayBuffer) ||
      signature[1].size !== 0
    ) {
      continue;
    }

    const signatureBase = [
      `${serializeItem(value[0][0]!)}: ${new URL(WEB_BOT_AUTH_DIRECTORY_URL).host}`,
      `${serializeItem(value[0][1]!)}: ${contentDigest}`,
      `"@signature-params": ${serializeInnerList(value)}`,
    ].join("\n");
    if (
      await crypto.subtle.verify(
        "Ed25519",
        key,
        signature[0],
        new TextEncoder().encode(signatureBase),
      )
    ) {
      return true;
    }
  }
  return false;
}

function isDirectorySignatureInput(
  value: InnerList | Item,
  keyId: string,
  now: number,
): value is InnerList {
  if (!isInnerList(value) || value[0].length !== 2) return false;
  const [authority, digest] = value[0];
  if (
    authority?.[0] !== "@authority" ||
    authority[1].size !== 1 ||
    authority[1].get("req") !== true ||
    digest?.[0] !== "content-digest" ||
    digest[1].size !== 0
  ) {
    return false;
  }

  const created = value[1].get("created");
  const expires = value[1].get("expires");
  return (
    typeof created === "number" &&
    Number.isSafeInteger(created) &&
    created <= now &&
    typeof expires === "number" &&
    Number.isSafeInteger(expires) &&
    expires > now &&
    expires > created &&
    value[1].get("keyid") === keyId &&
    value[1].get("alg") === "ed25519" &&
    value[1].get("tag") === WEB_BOT_AUTH_DIRECTORY_SIGNATURE_TAG
  );
}

async function verifyContentDigest(
  body: Uint8Array,
  contentDigest: string,
): Promise<boolean> {
  let dictionary: Dictionary;
  try {
    dictionary = parseDictionary(contentDigest);
  } catch {
    return false;
  }
  const value = dictionary.get("sha-256");
  if (
    !value ||
    isInnerList(value) ||
    !(value[0] instanceof ArrayBuffer) ||
    value[1].size !== 0
  ) {
    return false;
  }
  const expected = new Uint8Array(value[0]);
  const actual = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(body)),
  );
  if (expected.length !== actual.length) return false;
  let difference = 0;
  for (let index = 0; index < expected.length; index += 1) {
    difference |= expected[index]! ^ actual[index]!;
  }
  return difference === 0;
}

async function jwkThumbprint(
  value: JsonWebKey & { x: string },
): Promise<string> {
  const canonical = JSON.stringify({
    crv: value.crv,
    kty: value.kty,
    x: value.x,
  });
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)),
  );
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function importVerificationKey(value: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", value, { name: "Ed25519" }, true, [
    "verify",
  ]);
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength,
  ) as ArrayBuffer;
}

function parseHeaderDictionary(headers: Headers, name: string): Dictionary {
  const value = headers.get(name);
  if (!value) {
    throw new Error(`Web Bot Auth directory omitted ${name}.`);
  }
  try {
    return parseDictionary(value);
  } catch {
    throw new Error(`Web Bot Auth directory returned malformed ${name}.`);
  }
}

function createMemoryNonceStore(): NonceStore {
  const values = new Map<string, number>();
  return {
    consume(nonce, expires) {
      const now = Date.now();
      for (const [value, expiry] of values) {
        if (expiry <= now) values.delete(value);
      }
      if (values.has(nonce)) return true;
      values.set(nonce, expires);
      return false;
    },
  };
}

function isPublicEd25519Jwk(
  value: unknown,
): value is JsonWebKey & { kid: string; x: string } {
  if (!isRecord(value)) return false;
  if (
    value.kty !== "OKP" ||
    value.crv !== "Ed25519" ||
    typeof value.kid !== "string" ||
    value.kid.length === 0 ||
    typeof value.x !== "string" ||
    value.x.length === 0 ||
    "d" in value
  ) {
    return false;
  }
  if (value.alg !== undefined && value.alg !== "EdDSA") return false;
  if (value.use !== undefined && value.use !== "sig") return false;
  if (
    value.key_ops !== undefined &&
    (!Array.isArray(value.key_ops) || !value.key_ops.includes("verify"))
  ) {
    return false;
  }
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
