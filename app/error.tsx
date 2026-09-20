'use client';

/**
 * App Router error boundary for everything under `app/`.
 *
 * Next requires this to be a Client Component (`error.tsx` receives the
 * thrown error and a `reset` callback that re-renders the segment). Without
 * this file an unhandled render error falls back to Next's default error
 * screen, which leaks a stack trace in development and gives no way back to
 * the dashboard in production.
 *
 * The message shown is deliberately generic: `error.message` can carry detail
 * from a server-rendered path, and this page is one an operator might have
 * open next to somebody else's attack surface — it should not become a place
 * that echoes back unexpected internals.
 */

import { useEffect } from 'react';

export default function GlobalError({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  useEffect(() => {
    // Server-side render errors already hit the platform's log collector via
    // the route handler's own logging; this is the client-side counterpart so
    // a broken render is not silently invisible during development.
    console.error('Unhandled render error:', error);
  }, [error]);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-zinc-950 px-6 text-center text-zinc-100">
      <p className="font-mono text-xs uppercase tracking-widest text-rose-400">
        Something went wrong
      </p>
      <h1 className="text-2xl font-semibold">The dashboard hit an unexpected error.</h1>
      <p className="max-w-md text-sm text-zinc-400">
        Nothing was sent anywhere as a result of this. Try again, or reload the
        page if the problem persists.
      </p>
      {error.digest && (
        <p className="font-mono text-xs text-zinc-600">Reference: {error.digest}</p>
      )}
      <div className="mt-2 flex gap-3">
        <button
          type="button"
          onClick={retry}
          className="rounded-md bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-300 ring-1 ring-emerald-500/30 ring-inset transition hover:bg-emerald-500/20"
        >
          Try again
        </button>
        <a
          href="/passive-recon"
          className="rounded-md bg-white/5 px-4 py-2 text-sm font-medium text-zinc-200 ring-1 ring-white/10 ring-inset transition hover:bg-white/10"
        >
          Back to dashboard
        </a>
      </div>
    </main>
  );
}
