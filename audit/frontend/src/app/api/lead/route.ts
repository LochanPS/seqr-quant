const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function POST(req: Request) {
  let email: string | undefined;
  try {
    const body = await req.json();
    email = typeof body?.email === "string" ? body.email.trim() : undefined;
  } catch {
    return Response.json({ error: "Invalid request body" }, { status: 400 });
  }

  if (!email || !EMAIL_RE.test(email)) {
    return Response.json({ error: "Invalid email address" }, { status: 400 });
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.error("RESEND_API_KEY not set — lead capture cannot send email");
    return Response.json({ error: "Lead capture is not configured" }, { status: 503 });
  }

  const fromEmail = process.env.LEAD_FROM_EMAIL || "SeQr Labs <onboarding@resend.dev>";
  const notifyEmail = process.env.LEAD_NOTIFY_EMAIL || "lochan@seqr.in";

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [notifyEmail],
        reply_to: email,
        subject: "New SeQr scan request",
        text: `New scan request from ${email}\n\nSource: landing page final CTA`,
      }),
    });

    if (!res.ok) {
      const detail = await res.text();
      console.error("Resend API error:", res.status, detail);
      return Response.json({ error: "Failed to send. Try again shortly." }, { status: 502 });
    }

    return Response.json({ ok: true });
  } catch (err) {
    console.error("Resend request failed:", err);
    return Response.json({ error: "Failed to send. Try again shortly." }, { status: 502 });
  }
}
