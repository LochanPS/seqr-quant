import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service — SeQr Labs",
  description: "The terms governing use of the SeQr service.",
};

const UPDATED = "28 June 2026";

function H({ children }: { children: React.ReactNode }) {
  return <h2 className="mt-10 text-lg font-semibold text-foreground">{children}</h2>;
}
function P({ children }: { children: React.ReactNode }) {
  return <p className="mt-3 text-sm leading-7 text-muted-foreground">{children}</p>;
}

export default function TermsPage() {
  return (
    <main className="min-h-screen bg-background">
      <div className="mx-auto max-w-3xl px-6 py-20">
        <a href="/" className="text-sm text-quantum hover:underline">← SeQr Labs</a>
        <h1 className="mt-6 text-3xl font-bold text-foreground">Terms of Service</h1>
        <p className="mt-2 text-xs text-muted-foreground">Last updated: {UPDATED}</p>

        <P>
          These terms govern your use of the SeQr post-quantum cryptography assessment service
          (&quot;SeQr&quot;, the &quot;Service&quot;), operated by P S Lochan (pre-incorporation). By using
          SeQr you agree to these terms. SeQr is currently in beta.
        </P>

        <H>1. Authorised use — scanning</H>
        <P>
          You may submit a domain, host, or system to SeQr <b>only if you own it or are explicitly
          authorised to assess it.</b> You represent and warrant that you have such authority for every
          target you submit. You must not use SeQr to scan, probe, or assess any third-party system
          without authorisation. We may suspend or terminate accounts used for unauthorised scanning.
        </P>

        <H>2. Accounts</H>
        <P>
          You are responsible for keeping your credentials and API keys secure and for all activity under
          your account. Notify us promptly of any unauthorised use.
        </P>

        <H>3. Acceptable use</H>
        <P>
          Do not use the Service unlawfully, attempt to disrupt or reverse-engineer it, circumvent rate
          limits, or resell it without our written permission.
        </P>

        <H>4. Intellectual property &amp; your data</H>
        <P>
          SeQr and its software remain our property. Your account data and scan results remain yours; you
          grant us a limited licence to process them solely to provide the Service. Aggregate,
          de-identified statistics may be used to improve the product and for research (never in a way
          that identifies you or your systems).
        </P>

        <H>5. No warranty; informational output</H>
        <P>
          The Service is provided &quot;as is&quot; without warranties of any kind. SeQr&apos;s findings are
          informational assessments of cryptographic posture and do <b>not</b> guarantee security, and do
          not by themselves constitute regulatory compliance or legal advice. Harvest-Now-Decrypt-Later
          (HNDL) exposure scores are predictive risk metrics based on data-type endurance, not indicators
          of active interception or confirmed breach.
        </P>

        <H>6. Limitation of liability</H>
        <P>
          To the maximum extent permitted by law, SeQr is not liable for indirect, incidental, or
          consequential damages. During beta the Service is provided free or at nominal cost; our total
          liability is limited to the amount you paid us in the preceding three months (which may be zero).
        </P>

        <H>7. Indemnity</H>
        <P>
          You agree to indemnify us against claims arising from your unauthorised scanning of systems you
          do not own or lack authority to assess.
        </P>

        <H>8. Termination</H>
        <P>
          You may stop using the Service and delete your account at any time. We may suspend or terminate
          access for breach of these terms.
        </P>

        <H>9. Governing law</H>
        <P>
          These terms are governed by the laws of India. Courts at Bengaluru, Karnataka have exclusive
          jurisdiction.
        </P>

        <H>10. Changes</H>
        <P>We may update these terms; material changes will be posted here with a new date.</P>

        <H>Contact</H>
        <P>
          <a href="mailto:contact@seqrlabs.com" className="text-quantum hover:underline">contact@seqrlabs.com</a>
        </P>

        <div className="mt-12 border-t border-border pt-6 text-xs text-muted-foreground">
          <a href="/privacy" className="hover:underline">Privacy Policy</a>
        </div>
      </div>
    </main>
  );
}
