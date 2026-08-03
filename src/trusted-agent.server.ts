import * as Attestation from "mppx/attestation";
import * as Tap from "mppx/attestation/tap";
import * as WebBotAuth from "mppx/attestation/web-bot-auth";

const webBotAuthOrigin = new URL(
  process.env.WEB_BOT_AUTH_DIRECTORY_ORIGIN ?? "https://agents.tempo.xyz",
).origin;
const webBotAuthDirectoryUrl = new URL(
  "/.well-known/http-message-signatures-directory",
  webBotAuthOrigin,
).href;
const tapRegistryUrl =
  process.env.TAP_REGISTRY_URL ??
  "https://tap-registry-demo.vercel.app/.well-known/jwks";

const nonceStore = Attestation.NonceStore.memory();

const verifiers = {
  [Tap.Constants.protocol]: Tap.Server.verifier({
    keyResolver: (parameters) =>
      resolvePublicKey(tapRegistryUrl, "application/json", parameters),
    nonceStore,
  }),
  [WebBotAuth.Constants.protocol]: WebBotAuth.Server.verifier({
    keyResolver: ({ signatureAgent, ...parameters }) => {
      if (signatureAgent !== webBotAuthOrigin) return undefined;
      return resolvePublicKey(
        webBotAuthDirectoryUrl,
        "application/http-message-signatures-directory+json",
        parameters,
      );
    },
    nonceStore,
  }),
};

export type TrustedAgentIdentity = {
  tap: {
    intent: typeof Tap.Constants.intents.payment;
    keyId: string;
  };
  webBotAuth: {
    keyId: string;
    signatureAgent: string;
  };
};

export async function verifyTrustedAgent(
  request: Request,
): Promise<TrustedAgentIdentity | Response> {
  let verification: Awaited<
    ReturnType<typeof Attestation.Server.verify<typeof verifiers>>
  >;
  try {
    verification = await Attestation.Server.verify(request, verifiers);
  } catch {
    return new Response("Request attestation is invalid.", { status: 401 });
  }

  if (
    Object.values(verification.outcomes).some(
      (outcome) => outcome.status === "invalid",
    )
  )
    return new Response("Request attestation is invalid.", { status: 401 });

  const tap = verification.evidence.find(
    (evidence): evidence is Tap.Evidence =>
      evidence.protocol === Tap.Constants.protocol,
  );
  const webBotAuth = verification.evidence.find(
    (evidence): evidence is WebBotAuth.Evidence =>
      evidence.protocol === WebBotAuth.Constants.protocol,
  );

  if (
    !tap ||
    tap.value.intent !== Tap.Constants.intents.payment ||
    !webBotAuth ||
    webBotAuth.value.signatureAgent !== webBotAuthOrigin ||
    tap.value.nonce !== webBotAuth.value.nonce
  )
    return new Response(
      "TAP payment intent and Web Bot Auth identity are required.",
      { status: 403 },
    );

  return {
    tap: {
      intent: tap.value.intent,
      keyId: tap.value.keyId,
    },
    webBotAuth: {
      keyId: webBotAuth.value.keyId,
      signatureAgent: webBotAuth.value.signatureAgent,
    },
  };
}

async function resolvePublicKey(
  url: string,
  mediaType: string,
  parameters: {
    algorithm: Attestation.SignatureAlgorithm;
    keyId: string;
  },
): Promise<CryptoKey | undefined> {
  const response = await fetch(url, {
    headers: { Accept: mediaType },
  });
  if (!response.ok)
    throw new Error(`Key directory returned ${response.status}.`);

  const keySet: unknown = await response.json();
  if (!isKeySet(keySet)) throw new Error("Key directory is malformed.");
  const key = keySet.keys.find(
    (candidate) => candidate.kid === parameters.keyId,
  );
  if (!key || "d" in key || key.ext === false) return undefined;
  if (key.use !== undefined && key.use !== "sig") return undefined;
  if (key.key_ops !== undefined && !key.key_ops.includes("verify"))
    return undefined;

  if (parameters.algorithm === Attestation.Algorithms.ed25519) {
    if (
      key.kty !== "OKP" ||
      key.crv !== "Ed25519" ||
      (key.alg !== undefined && key.alg !== "EdDSA")
    )
      return undefined;
    return crypto.subtle.importKey("jwk", key, "Ed25519", true, ["verify"]);
  }

  if (parameters.algorithm === Attestation.Algorithms.rsaPssSha512) {
    if (key.kty !== "RSA" || (key.alg !== undefined && key.alg !== "PS512"))
      return undefined;
    return crypto.subtle.importKey(
      "jwk",
      key,
      { hash: "SHA-512", name: "RSA-PSS" },
      true,
      ["verify"],
    );
  }

  return undefined;
}

type DirectoryKey = JsonWebKey & { kid: string };

function isKeySet(value: unknown): value is { keys: DirectoryKey[] } {
  return (
    typeof value === "object" &&
    value !== null &&
    "keys" in value &&
    Array.isArray(value.keys) &&
    value.keys.every(
      (key) =>
        typeof key === "object" &&
        key !== null &&
        "kid" in key &&
        typeof key.kid === "string",
    )
  );
}
