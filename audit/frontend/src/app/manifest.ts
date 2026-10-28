import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "SeQr Labs — Quantum Cryptography Audit",
    short_name: "SeQr",
    description:
      "Discover, score, and remediate quantum-vulnerable cryptography across your infrastructure.",
    start_url: "/",
    display: "standalone",
    background_color: "#0a0a0f",
    theme_color: "#0a0a0f",
    icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml" }],
  };
}
