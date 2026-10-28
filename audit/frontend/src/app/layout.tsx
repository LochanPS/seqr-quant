import type { Metadata } from "next";
import localFont from "next/font/local";
import { Schibsted_Grotesk } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/ThemeProvider";
import { QueryProvider } from "@/components/QueryProvider";
import { ToastProvider } from "@/components/ui/toast";
import { TooltipProvider } from "@/components/ui/tooltip";

const geist = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-geist",
  weight: "100 900",
});
const mono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-mono",
  weight: "100 900",
});
// Display typeface for marketing headlines (scoped via .font-display utility).
const display = Schibsted_Grotesk({
  subsets: ["latin"],
  weight: ["400", "500", "700", "800", "900"],
  variable: "--font-display",
  display: "swap",
});

export const metadata: Metadata = {
  title: "SeQr Labs — Quantum Cryptography Audit",
  description:
    "Discover, score, and remediate quantum-vulnerable cryptography across your infrastructure.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geist.variable} ${mono.variable} ${display.variable} font-sans antialiased`}
      >
        <ThemeProvider attribute="class" defaultTheme="dark" forcedTheme="dark">
          <QueryProvider>
            <TooltipProvider delayDuration={200}>
              <ToastProvider>{children}</ToastProvider>
            </TooltipProvider>
          </QueryProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
