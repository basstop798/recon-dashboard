/**
 * App Router 404 page.
 *
 * Without this, an unmatched route falls back to Next's default not-found
 * screen, which is off-brand and gives no way back to the dashboard.
 */

export default function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-zinc-950 px-6 text-center text-zinc-100">
      <p className="font-mono text-xs uppercase tracking-widest text-zinc-500">404</p>
      <h1 className="text-2xl font-semibold">This page does not exist.</h1>
      <p className="max-w-md text-sm text-zinc-400">
        Nothing lives at this path. The dashboard itself is at{' '}
        <code className="rounded bg-zinc-900 px-1.5 py-0.5 font-mono text-emerald-300 ring-1 ring-white/10">
          /passive-recon
        </code>
        .
      </p>
      <a
        href="/passive-recon"
        className="mt-2 rounded-md bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-300 ring-1 ring-emerald-500/30 ring-inset transition hover:bg-emerald-500/20"
      >
        Back to dashboard
      </a>
    </main>
  );
}
