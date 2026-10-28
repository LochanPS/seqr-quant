export async function POST(req: Request) {
  // Default to the live public backend so a missing/stale env can't silently 500.
  const backendUrl = process.env.BACKEND_URL || "https://api.seqrlabs.com";

  let domain: string | undefined;
  try {
    ({ domain } = await req.json());
  } catch {
    return Response.json({ error: "bad_request", message: "Invalid JSON body." }, { status: 400 });
  }
  if (!domain || typeof domain !== "string") {
    return Response.json({ error: "bad_request", message: "Missing 'domain'." }, { status: 400 });
  }

  try {
    const res = await fetch(`${backendUrl}/api/v1/public/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
      signal: AbortSignal.timeout(45000),
    });
    // Pass the backend's body + status through, even for non-2xx (it returns
    // structured {error, message} for timeouts/WAF blocks the UI already renders).
    const text = await res.text();
    try {
      return Response.json(JSON.parse(text), { status: res.status });
    } catch {
      return Response.json(
        { error: "upstream_error", message: text.slice(0, 500) || "Scan backend returned no body." },
        { status: res.status >= 400 ? res.status : 502 },
      );
    }
  } catch (e) {
    // fetch itself failed (backend unreachable / DNS / timeout) — surface it, don't 500 blindly.
    const message = e instanceof Error ? e.message : "Scan backend unreachable.";
    return Response.json({ error: "backend_unreachable", message }, { status: 502 });
  }
}
