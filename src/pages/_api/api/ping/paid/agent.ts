import { Expires } from "mppx/server";
import { mppx } from "../../../../../mppx.server";
import { verifyTrustedAgent } from "../../../../../trusted-agent.server";

export async function GET(request: Request) {
  const agent = await verifyTrustedAgent(request);
  if (agent instanceof Response) return agent;

  const result = await mppx.charge({
    amount: "0.1",
    currency: import.meta.env.VITE_DEFAULT_CURRENCY!,
    expires: Expires.minutes(5),
    description: "Ping endpoint access",
  })(request);

  if (result.status === 402) return result.challenge;

  return result.withReceipt(
    Response.json({
      agent,
      message: "tm! thanks for paying",
    }),
  );
}
