import { Expires } from "mppx/server";
import { mppx } from "../../../../../mppx.server";
import {
  createEnvironmentNonceStore,
  createTrustedAgentPaymentHandler,
} from "../../../../../trusted-agent-payment.server";

const handler = createTrustedAgentPaymentHandler(
  async (request) => {
    const result = await mppx.charge({
      amount: "0.1",
      currency: import.meta.env.VITE_DEFAULT_CURRENCY!,
      description: "Trusted agent ping endpoint access",
      expires: Expires.minutes(5),
    })(request);
    if (result.status === 402) return result.challenge;
    return result.withReceipt(
      new Response("tm! trusted agent identity and payment verified"),
    );
  },
  { nonceStore: createEnvironmentNonceStore() },
);

export function GET(request: Request) {
  return handler(request);
}
