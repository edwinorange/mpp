import * as Attestation from "mppx/attestation";
import * as Tap from "mppx/attestation/tap";
import * as WebBotAuth from "mppx/attestation/web-bot-auth";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyTrustedAgent } from "./trusted-agent.server";

const signatureAgent = "https://agents.tempo.xyz";

describe("verifyTrustedAgent", () => {
  let tapKeys: CryptoKeyPair;
  let webBotAuthKeys: CryptoKeyPair;
  let tapKeyId: string;
  let webBotAuthKeyId: string;

  beforeEach(async () => {
    tapKeys = await keyPair();
    webBotAuthKeys = await keyPair();
    tapKeyId = "tap-agent";
    webBotAuthKeyId = await thumbprint(webBotAuthKeys.publicKey);

    const tapJwk = await publicJwk(tapKeys.publicKey, tapKeyId);
    const webBotAuthJwk = await publicJwk(
      webBotAuthKeys.publicKey,
      webBotAuthKeyId,
    );
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url === "https://tap-registry-demo.vercel.app/.well-known/jwks")
        return Response.json({ keys: [tapJwk] });
      if (
        url ===
        "https://agents.tempo.xyz/.well-known/http-message-signatures-directory"
      )
        return Response.json({ keys: [webBotAuthJwk] });
      return new Response(null, { status: 404 });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("requires both Web Bot Auth and TAP payment intent", async () => {
    for (const request of [
      new Request("https://mpp.dev/api/ping/paid/agent"),
      await webBotAuthSigner().sign(
        new Request("https://mpp.dev/api/ping/paid/agent"),
      ),
      await tapSigner().sign(
        new Request("https://mpp.dev/api/ping/paid/agent"),
      ),
    ]) {
      const result = await verifyTrustedAgent(request);
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(403);
    }
  });

  it("returns the identity derived from both verified signatures", async () => {
    const request = await Attestation.Client.composeSigners(
      webBotAuthSigner(),
      tapSigner(),
    ).sign(new Request("https://mpp.dev/api/ping/paid/agent"));

    await expect(verifyTrustedAgent(request)).resolves.toEqual({
      tap: {
        intent: "payment",
        keyId: tapKeyId,
      },
      webBotAuth: {
        keyId: webBotAuthKeyId,
        signatureAgent,
      },
    });
  });

  it("requires TAP payment intent", async () => {
    const request = await Attestation.Client.composeSigners(
      webBotAuthSigner(),
      Tap.Client.signer({
        intent: Tap.Constants.intents.browse,
        key: tapKeys.privateKey,
        keyId: tapKeyId,
      }),
    ).sign(new Request("https://mpp.dev/api/ping/paid/agent"));

    const result = await verifyTrustedAgent(request);
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(403);
  });

  it("requires TAP and Web Bot Auth to share a request nonce", async () => {
    let request = await webBotAuthSigner().sign(
      new Request("https://mpp.dev/api/ping/paid/agent"),
    );
    request = await tapSigner().sign(request);

    const result = await verifyTrustedAgent(request);
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(403);
  });

  it("rejects a replay of a previously accepted request", async () => {
    const request = await Attestation.Client.composeSigners(
      webBotAuthSigner(),
      tapSigner(),
    ).sign(new Request("https://mpp.dev/api/ping/paid/agent"));

    expect(await verifyTrustedAgent(request)).not.toBeInstanceOf(Response);
    const replay = await verifyTrustedAgent(request);
    expect(replay).toBeInstanceOf(Response);
    expect((replay as Response).status).toBe(401);
  });

  it("does not resolve keys from an untrusted Signature-Agent origin", async () => {
    const request = await Attestation.Client.composeSigners(
      WebBotAuth.Client.signer({
        key: webBotAuthKeys.privateKey,
        keyId: webBotAuthKeyId,
        signatureAgent: "https://attacker.example",
      }),
      tapSigner(),
    ).sign(new Request("https://mpp.dev/api/ping/paid/agent"));

    const result = await verifyTrustedAgent(request);
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(403);
    expect(vi.mocked(fetch)).not.toHaveBeenCalledWith(
      expect.stringContaining("attacker.example"),
      expect.anything(),
    );
  });

  function tapSigner() {
    return Tap.Client.signer({
      intent: Tap.Constants.intents.payment,
      key: tapKeys.privateKey,
      keyId: tapKeyId,
    });
  }

  function webBotAuthSigner() {
    return WebBotAuth.Client.signer({
      key: webBotAuthKeys.privateKey,
      keyId: webBotAuthKeyId,
      signatureAgent,
    });
  }
});

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
}

async function publicJwk(key: CryptoKey, kid: string) {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  delete jwk.alg;
  return {
    ...jwk,
    key_ops: ["verify"],
    kid,
    use: "sig",
  };
}

async function thumbprint(key: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical),
  );
  return Buffer.from(digest).toString("base64url");
}
