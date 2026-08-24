import { NextRequest, NextResponse } from "next/server";

const API = process.env.SNOWIMPACT_API || "http://api:8080";
const KEY = process.env.SNOWIMPACT_API_KEY || "";

function headers(extra: Record<string, string> = {}) {
  return { ...extra, ...(KEY ? { "X-SnowImpact-Key": KEY } : {}) };
}

export async function GET() {
  const response = await fetch(`${API}/api/v1/analyses?limit=25`, {
    headers: headers(),
    cache: "no-store",
  });
  const body = await response.text();
  return new NextResponse(body, {
    status: response.status,
    headers: { "Content-Type": response.headers.get("content-type") || "application/json" },
  });
}

export async function POST(request: NextRequest) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    return NextResponse.json({ error: "application/json required" }, { status: 415 });
  }
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (origin && host && !origin.includes(`://${host}`)) {
    return NextResponse.json({ error: "cross-origin request rejected" }, { status: 403 });
  }
  const payload = await request.json();
  const response = await fetch(`${API}/api/v1/analyses`, {
    method: "POST",
    headers: headers({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  const body = await response.text();
  return new NextResponse(body, {
    status: response.status,
    headers: { "Content-Type": response.headers.get("content-type") || "application/json" },
  });
}
