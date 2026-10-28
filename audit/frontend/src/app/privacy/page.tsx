import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy — SeQr Labs",
  description: "How SeQr Labs collects, uses, and protects your data.",
};

const UPDATED = "28 June 2026";

function H({ children }: { children: React.ReactNode }) {
  return <h2 className="mt-10 text-lg font-semibold text-foreground">{children}</h2>;
}
function P({ children }: { children: React.ReactNode }) {
  return <p className="mt-3 text-sm leading-7 text-muted-foreground">{children}</p>;
}
function LI({ children }: { children: React.ReactNode }) {
  return <li className="mt-2 text-sm leading-7 text-muted-foreground">{children}</li>;
}

export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-background">
      <div className="mx-auto max-w-3xl px-6 py-20">
        <a href="/" className="text-sm text-quantum hover:underline">← SeQr Labs</a>
        <h1 className="mt-6 text-3xl font-bold text-foreground">Privacy Policy</h1>
        <p className="mt-2 text-xs text-muted-foreground">Last updated: {UPDATED}</p>

        <P>
          This policy explains how SeQr Labs (&quot;SeQr&quot;, &quot;we&quot;) handles data for the SeQr
          post-quantum cryptography (PQC) assessment service. SeQr is operated by P S Lochan
          (pre-incorporation) and is currently in beta.
        </P>

        <H>What we collect</H>
        <ul className="list-disc pl-5">
          <LI><b>Account data</b> — name, email, and organisation name/sector you provide at sign-up.</LI>
          <LI><b>Scan inputs</b> — the domains, hosts, or endpoints you submit for assessment.</LI>
          <LI>
            <b>Scan outputs</b> — technical cryptographic metadata of those endpoints (TLS versions,
            certificate algorithms, key-exchange groups, CDN, and derived risk findings). This is
            technical configuration data, not personal data.
          </LI>
          <LI><b>Operational logs</b> — IP address and timestamps, used for security and rate limiting.</LI>
        </ul>

        <H>What we do not collect</H>
        <P>
          SeQr observes only what a public TLS handshake exposes. We do not exploit systems, capture
          application payloads, or collect the personal data of your end-users. Scans are passive,
          rate-limited connections equivalent to an ordinary client.
        </P>

        <H>How we use data</H>
        <P>
          To deliver the service (generate your Cryptographic Bill of Materials, risk scores, and
          reports), to secure and rate-limit the platform, and to improve the product. We do not sell
          your data or use it for advertising.
        </P>

        <H>Sub-processors</H>
        <P>
          We use third-party infrastructure providers to run the service: application hosting, managed
          PostgreSQL database, managed Redis, and frontend hosting. Each processes data only to provide
          hosting to us.
        </P>

        <H>Where data is processed</H>
        <P>
          During beta, data may be processed on cloud infrastructure located outside India. We intend to
          host production data in an India region (ap-south-1) before onboarding regulated customers, in
          line with data-localisation expectations. If India-only processing is a requirement for you,
          contact us before signing up.
        </P>

        <H>Retention</H>
        <P>
          We keep account data while your account is active and for up to 90 days after closure. You can
          delete your assets and scan data at any time from the dashboard; deletion is permanent.
        </P>

        <H>Security</H>
        <P>
          Passwords are hashed (bcrypt), API keys are stored only as hashes, data is encrypted in transit
          (TLS), and every tenant&apos;s data is isolated by organisation. No system is perfectly secure;
          we work to protect your data using reasonable safeguards.
        </P>

        <H>Your rights</H>
        <P>
          You may request access to, correction of, or erasure of your personal data, and may withdraw
          consent, by emailing{" "}
          <a href="mailto:contact@seqrlabs.com" className="text-quantum hover:underline">contact@seqrlabs.com</a>.
          Under India&apos;s Digital Personal Data Protection Act 2023, you also have the right to
          grievance redressal.
        </P>

        <H>Grievance Officer</H>
        <P>
          P S Lochan — <a href="mailto:contact@seqrlabs.com" className="text-quantum hover:underline">contact@seqrlabs.com</a>.
          We respond to data-protection grievances within the timelines required by applicable law.
        </P>

        <H>Children</H>
        <P>SeQr is not intended for individuals under 18.</P>

        <H>Changes</H>
        <P>We may update this policy; material changes will be posted on this page with a new date.</P>

        <H>Contact</H>
        <P>
          <a href="mailto:contact@seqrlabs.com" className="text-quantum hover:underline">contact@seqrlabs.com</a>
        </P>

        <div className="mt-12 border-t border-border pt-6 text-xs text-muted-foreground">
          <a href="/terms" className="hover:underline">Terms of Service</a>
        </div>
      </div>
    </main>
  );
}
