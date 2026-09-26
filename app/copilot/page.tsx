'use client';

/**
 * AI Security Co-pilot — the page.
 *
 * Non-expert framing: "an AI security co-pilot for small businesses and startups
 * that cannot afford a security team." A founder pastes findings (or loads the
 * demo scan), and gets a ranked, plain-language report with cited fixes.
 *
 * Two input paths, both feeding the SAME source-agnostic /api/analyze:
 *   • "Load demo scan"  -> bundled demo-data.json (offline-safe, the demo net).
 *   • Paste findings    -> plan B path; also where a live BulletRecon scan's
 *                          findings would be dropped in on build day (plan A).
 *
 * Everything that makes this score — grounding, redaction, provider fallback —
 * lives server-side behind /api/analyze; this page just drives it and renders.
 */

import { useCallback, useState } from 'react';

import type { Finding } from '@/lib/passive-recon/types';
import type { CopilotReport } from '@/lib/ai/types';
import demoData from '@/lib/ai/demo-data.json';

import {
  AssessmentCard,
  RedactionBanner,
  ReportMeta,
  RiskScore,
  cx,
} from './components/report';

interface AnalyzeResponse {
  report: CopilotReport;
  redaction: { total: number; counts: Record<string, number> };
  target: string | null;
}

const BUTTON_PRIMARY =
  'inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-emerald-950 transition-colors hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50';
const BUTTON_SECONDARY =
  'inline-flex items-center justify-center gap-2 rounded-lg bg-white/5 px-4 py-2 text-sm font-medium text-zinc-300 ring-1 ring-inset ring-white/10 transition-colors hover:bg-white/10 hover:text-white disabled:cursor-not-allowed disabled:opacity-50';

export default function CopilotPage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [target, setTarget] = useState<string | null>(null);

  const runAnalysis = useCallback(async (findings: Finding[], targetLabel?: string) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findings, target: targetLabel }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.detail || data?.error || `Request failed (${res.status})`);
      }
      setResult(data as AnalyzeResponse);
      setTarget((data as AnalyzeResponse).target);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDemo = useCallback(() => {
    setInput(JSON.stringify(demoData.findings, null, 2));
    void runAnalysis(demoData.findings as Finding[], demoData.target);
  }, [runAnalysis]);

  const analyzePasted = useCallback(() => {
    let findings: Finding[];
    try {
      const parsed = JSON.parse(input);
      // Accept either a raw array or a { findings: [...] } wrapper.
      findings = Array.isArray(parsed) ? parsed : parsed.findings;
      if (!Array.isArray(findings) || findings.length === 0) {
        throw new Error('Expected a non-empty array of findings.');
      }
    } catch (err) {
      setError(
        `Could not read that input as findings JSON: ${err instanceof Error ? err.message : String(err)}`,
      );
      return;
    }
    void runAnalysis(findings);
  }, [input, runAnalysis]);

  return (
    <main className="mx-auto w-full max-w-5xl px-4 py-10 sm:px-6 lg:py-14">
      <header className="mb-8">
        <div className="flex items-center gap-2">
          <span className="rounded-md bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider text-emerald-300 ring-1 ring-inset ring-emerald-500/25">
            AI Co-pilot
          </span>
          <span className="text-[11px] uppercase tracking-wider text-zinc-500">Built on BulletRecon</span>
        </div>
        <h1 className="mt-3 text-2xl font-bold tracking-tight text-zinc-50 sm:text-3xl">
          Your security team in a box
        </h1>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-zinc-400">
          For small businesses and startups with no security team. Paste your recon findings and get a
          ranked, plain-language report — what each issue means for your business, how to fix it, and a
          link to the real advisory it is based on. No jargon, no guesswork.
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-[1fr]">
        <section className="rounded-xl border border-white/10 bg-zinc-900 p-5 shadow-lg shadow-black/20 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-semibold tracking-tight text-zinc-50">Findings input</h2>
              <p className="mt-1 text-sm text-zinc-400">
                Load the demo scan, or paste findings JSON from a BulletRecon export.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={loadDemo} disabled={loading} className={BUTTON_SECONDARY}>
                Load demo scan
              </button>
              <button type="button" onClick={analyzePasted} disabled={loading || !input.trim()} className={BUTTON_PRIMARY}>
                {loading ? 'Analyzing…' : 'Analyze with AI'}
              </button>
            </div>
          </div>

          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            placeholder='Paste findings JSON here, e.g. [{ "id": "...", "module": "mail", "severity": "high", "title": "...", "detail": "..." }] — or click "Load demo scan".'
            className="mt-4 h-48 w-full resize-y rounded-lg border border-white/10 bg-zinc-950/60 p-3 font-mono text-[13px] text-zinc-200 placeholder:text-zinc-600 focus:border-emerald-500/40 focus:outline-none focus:ring-1 focus:ring-emerald-500/40"
          />

          {error && (
            <div className="mt-4 rounded-lg border border-rose-500/20 bg-rose-500/5 px-4 py-3 text-sm text-rose-300">
              {error}
            </div>
          )}
        </section>

        {result && (
          <section className="space-y-6">
            <RedactionBanner total={result.redaction.total} counts={result.redaction.counts} />

            <div className="grid gap-6 sm:grid-cols-[minmax(0,240px)_1fr] sm:items-start">
              <RiskScore score={result.report.riskScore} />
              <div className="rounded-xl border border-white/10 bg-zinc-900 p-6 shadow-lg shadow-black/20">
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-400">
                  Executive summary{target ? ` — ${target}` : ''}
                </p>
                <p className="mt-3 text-sm leading-relaxed text-zinc-200">
                  {result.report.executiveSummary}
                </p>
              </div>
            </div>

            <ReportMeta report={result.report} />

            <div className="space-y-4">
              <h2 className={cx('text-sm font-semibold uppercase tracking-wider text-zinc-400')}>
                {result.report.assessments.length} issue
                {result.report.assessments.length === 1 ? '' : 's'}, most urgent first
              </h2>
              {result.report.assessments.map((assessment) => (
                <AssessmentCard key={assessment.findingId} assessment={assessment} />
              ))}
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
