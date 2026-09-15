import { redirect } from 'next/navigation';

/**
 * The dashboard lives at /passive-recon; this route just forwards to it.
 *
 * This page previously hosted an active-scan prototype (TCP port scanning,
 * directory brute-forcing and a shell-exec'd `ping`), backed by /api/scan.
 * Both were removed because they broke the passive-only guarantee this tool
 * makes: most bug bounty programs forbid unauthorized active scanning, so
 * shipping that behaviour risked getting hunters scope-violated or banned.
 */
export default function Home() {
  redirect('/passive-recon');
}
