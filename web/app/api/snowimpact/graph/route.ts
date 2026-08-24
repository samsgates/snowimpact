import { NextResponse } from "next/server";

const API = process.env.SNOWIMPACT_API || "http://api:8080";
const KEY = process.env.SNOWIMPACT_API_KEY || "";

export async function GET() {
  const response = await fetch(`${API}/api/v1/graph`, {
    headers: KEY ? { "X-SnowImpact-Key": KEY } : {},
    cache: "no-store",
  });
  const body = await response.text();
  return new NextResponse(body, {
    status: response.status,
    headers: { "Content-Type": response.headers.get("content-type") || "application/json" },
  });
}
