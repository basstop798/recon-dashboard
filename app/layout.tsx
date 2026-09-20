import type { Metadata, Viewport } from "next";
import { Geist_Mono, Inter } from "next/font/google";
import "./globals.css";

// Inter for the interface; Geist Mono only for technical values (hosts, URLs,
// IPs, hashes) — see the typography rule in app/passive-recon/components/ui.tsx.
const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "BulletRecon — one-click passive reconnaissance",
  description:
    "Aggregated passive OSINT for a single domain: subdomains, takeover candidates, DNS and mail posture, registration data, technology fingerprint, JavaScript secrets, archived URLs and search dorks.",
  // A recon dashboard should not end up in anyone's index — the URLs it holds
  // are somebody else's attack surface.
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  colorScheme: "dark",
  themeColor: "#09090b",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col bg-zinc-950 font-sans text-zinc-100">
        {children}
      </body>
    </html>
  );
}
