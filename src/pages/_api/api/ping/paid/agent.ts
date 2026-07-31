export function GET() {
  return new Response("Trusted agent authorization is not configured.", {
    status: 403,
  });
}
