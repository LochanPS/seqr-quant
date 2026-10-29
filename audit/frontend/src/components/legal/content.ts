// Legal copy, carried over verbatim from the previous site and lightly re-punctuated.
// Inline markup: **bold** and [label](href).

export type Block = { p: string } | { ul: string[] };
export type LegalDoc = { title: string; updated: string; intro: Block[]; sections: { heading: string; blocks: Block[] }[] };

export const PRIVACY: LegalDoc = {
  "title": "Privacy Policy",
  "updated": "28 June 2026",
  "intro": [
    {
      "p": "This policy explains how SeQr Labs (\"SeQr\", \"we\") handles data for the SeQr post-quantum cryptography (PQC) assessment service. SeQr is operated by P S Lochan (pre-incorporation) and is currently in beta."
    }
  ],
  "sections": [
    {
      "heading": "What we collect",
      "blocks": [
        {
          "ul": [
            "**Account data**: name, email, and organisation name/sector you provide at sign-up.",
            "**Scan inputs**: the domains, hosts, or endpoints you submit for assessment.",
            "**Scan outputs**: technical cryptographic metadata of those endpoints (TLS versions, certificate algorithms, key-exchange groups, CDN, and derived risk findings). This is technical configuration data, not personal data.",
            "**Operational logs**: IP address and timestamps, used for security and rate limiting."
          ]
        }
      ]
    },
    {
      "heading": "What we do not collect",
      "blocks": [
        {
          "p": "SeQr observes only what a public TLS handshake exposes. We do not exploit systems, capture application payloads, or collect the personal data of your end-users. Scans are passive, rate-limited connections equivalent to an ordinary client."
        }
      ]
    },
    {
      "heading": "How we use data",
      "blocks": [
        {
          "p": "To deliver the service (generate your Cryptographic Bill of Materials, risk scores, and reports), to secure and rate-limit the platform, and to improve the product. We do not sell your data or use it for advertising."
        }
      ]
    },
    {
      "heading": "Sub-processors",
      "blocks": [
        {
          "p": "We use third-party infrastructure providers to run the service: application hosting, managed PostgreSQL database, managed Redis, and frontend hosting. Each processes data only to provide hosting to us."
        }
      ]
    },
    {
      "heading": "Where data is processed",
      "blocks": [
        {
          "p": "During beta, data may be processed on cloud infrastructure located outside India. We intend to host production data in an India region (ap-south-1) before onboarding regulated customers, in line with data-localisation expectations. If India-only processing is a requirement for you, contact us before signing up."
        }
      ]
    },
    {
      "heading": "Retention",
      "blocks": [
        {
          "p": "We keep account data while your account is active and for up to 90 days after closure. You can delete your assets and scan data at any time from the dashboard; deletion is permanent."
        }
      ]
    },
    {
      "heading": "Security",
      "blocks": [
        {
          "p": "Passwords are hashed (bcrypt), API keys are stored only as hashes, data is encrypted in transit (TLS), and every tenant's data is isolated by organisation. No system is perfectly secure; we work to protect your data using reasonable safeguards."
        }
      ]
    },
    {
      "heading": "Your rights",
      "blocks": [
        {
          "p": "You may request access to, correction of, or erasure of your personal data, and may withdraw consent, by emailing [contact@seqrlabs.com](mailto:contact@seqrlabs.com). Under India's Digital Personal Data Protection Act 2023, you also have the right to grievance redressal."
        }
      ]
    },
    {
      "heading": "Grievance Officer",
      "blocks": [
        {
          "p": "P S Lochan, [contact@seqrlabs.com](mailto:contact@seqrlabs.com). We respond to data-protection grievances within the timelines required by applicable law."
        }
      ]
    },
    {
      "heading": "Children",
      "blocks": [
        {
          "p": "SeQr is not intended for individuals under 18."
        }
      ]
    },
    {
      "heading": "Changes",
      "blocks": [
        {
          "p": "We may update this policy; material changes will be posted on this page with a new date."
        }
      ]
    },
    {
      "heading": "Contact",
      "blocks": [
        {
          "p": "[contact@seqrlabs.com](mailto:contact@seqrlabs.com)"
        }
      ]
    }
  ]
};

export const TERMS: LegalDoc = {
  "title": "Terms of Service",
  "updated": "28 June 2026",
  "intro": [
    {
      "p": "These terms govern your use of the SeQr post-quantum cryptography assessment service (\"SeQr\", the \"Service\"), operated by P S Lochan (pre-incorporation). By using SeQr you agree to these terms. SeQr is currently in beta."
    }
  ],
  "sections": [
    {
      "heading": "1. Authorised use, scanning",
      "blocks": [
        {
          "p": "You may submit a domain, host, or system to SeQr **only if you own it or are explicitly authorised to assess it.** You represent and warrant that you have such authority for every target you submit. You must not use SeQr to scan, probe, or assess any third-party system without authorisation. We may suspend or terminate accounts used for unauthorised scanning."
        }
      ]
    },
    {
      "heading": "2. Accounts",
      "blocks": [
        {
          "p": "You are responsible for keeping your credentials and API keys secure and for all activity under your account. Notify us promptly of any unauthorised use."
        }
      ]
    },
    {
      "heading": "3. Acceptable use",
      "blocks": [
        {
          "p": "Do not use the Service unlawfully, attempt to disrupt or reverse-engineer it, circumvent rate limits, or resell it without our written permission."
        }
      ]
    },
    {
      "heading": "4. Intellectual property & your data",
      "blocks": [
        {
          "p": "SeQr and its software remain our property. Your account data and scan results remain yours; you grant us a limited licence to process them solely to provide the Service. Aggregate, de-identified statistics may be used to improve the product and for research (never in a way that identifies you or your systems)."
        }
      ]
    },
    {
      "heading": "5. No warranty; informational output",
      "blocks": [
        {
          "p": "The Service is provided \"as is\" without warranties of any kind. SeQr's findings are informational assessments of cryptographic posture and do **not** guarantee security, and do not by themselves constitute regulatory compliance or legal advice. Harvest-Now-Decrypt-Later (HNDL) exposure scores are predictive risk metrics based on data-type endurance, not indicators of active interception or confirmed breach."
        }
      ]
    },
    {
      "heading": "6. Limitation of liability",
      "blocks": [
        {
          "p": "To the maximum extent permitted by law, SeQr is not liable for indirect, incidental, or consequential damages. During beta the Service is provided free or at nominal cost; our total liability is limited to the amount you paid us in the preceding three months (which may be zero)."
        }
      ]
    },
    {
      "heading": "7. Indemnity",
      "blocks": [
        {
          "p": "You agree to indemnify us against claims arising from your unauthorised scanning of systems you do not own or lack authority to assess."
        }
      ]
    },
    {
      "heading": "8. Termination",
      "blocks": [
        {
          "p": "You may stop using the Service and delete your account at any time. We may suspend or terminate access for breach of these terms."
        }
      ]
    },
    {
      "heading": "9. Governing law",
      "blocks": [
        {
          "p": "These terms are governed by the laws of India. Courts at Bengaluru, Karnataka have exclusive jurisdiction."
        }
      ]
    },
    {
      "heading": "10. Changes",
      "blocks": [
        {
          "p": "We may update these terms; material changes will be posted here with a new date."
        }
      ]
    },
    {
      "heading": "Contact",
      "blocks": [
        {
          "p": "[contact@seqrlabs.com](mailto:contact@seqrlabs.com)"
        }
      ]
    }
  ]
};

