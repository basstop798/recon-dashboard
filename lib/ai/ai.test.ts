import { describe, expect, it } from 'vitest';

import demo from './demo-data.json';
import { analyze, mockAdvisor } from './advisor';
import { groundFinding, groundFindings, knowledgeBase } from './grounding';
import { redactFindings, redactText } from './redact';
import { parseReport } from './schema';
import type { Finding } from './types';

const findings = demo.findings as Finding[];

describe('knowledge base integrity', () => {
  const kb = knowledgeBase();

  it('has a meaningful number of entries', () => {
    expect(kb.length).toBeGreaterThanOrEqual(20);
  });

  it('every entry has a real citation URL', () => {
    for (const entry of kb) {
      expect(entry.reference).toMatch(/^https?:\/\//);
      expect(entry.remediation.length).toBeGreaterThan(0);
      expect(entry.keywords.length).toBeGreaterThan(0);
    }
  });

  it('has no duplicate ids', () => {
    const ids = kb.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('grounding — findings match real advisories', () => {
  it('grounds the AWS key finding to the hard-coded-secrets entry', () => {
    const finding = findings.find((f) => f.id.startsWith('secret:'))!;
    const { match } = groundFinding(finding);
    expect(match?.id).toBe('CWE-798-SECRETS');
    expect(match?.reference).toMatch(/^https?:\/\//);
  });

  it('grounds the permissive SPF finding', () => {
    const finding = findings.find((f) => f.id === 'mail:spf-permissive')!;
    const { match } = groundFinding(finding);
    expect(match?.id).toBe('SPF-PERMISSIVE');
  });

  it('grounds the subdomain takeover finding', () => {
    const finding = findings.find((f) => f.id.startsWith('takeover:'))!;
    const { match } = groundFinding(finding);
    expect(match?.id).toBe('SUBDOMAIN-TAKEOVER');
  });

  it('grounds the missing-HSTS header finding', () => {
    const finding = findings.find((f) => f.id === 'header:Strict-Transport-Security')!;
    const { match } = groundFinding(finding);
    expect(match?.id).toBe('CWE-693-HEADERS');
  });

  it('grounds a majority of the demo findings', () => {
    const grounded = groundFindings(findings);
    const rate = grounded.filter((g) => g.match).length / grounded.length;
    expect(rate).toBeGreaterThanOrEqual(0.7);
  });

  it('does not force a citation on unrelated text', () => {
    const bogus: Finding = {
      id: 'noise:xyz',
      module: 'meta',
      severity: 'info',
      title: 'A completely unrelated observation about nothing',
      detail: 'Lorem ipsum dolor sit amet, nothing technical here at all.',
    };
    expect(groundFinding(bogus).match).toBeNull();
  });
});

describe('redaction — sensitive data is masked', () => {
  it('masks IPv4 addresses', () => {
    const { value, counts } = redactText('host at 10.0.14.22 and 8.8.8.8');
    expect(value).not.toContain('10.0.14.22');
    expect(value).toContain('[REDACTED-IP]');
    expect(counts.ipv4).toBe(2);
  });

  it('masks emails and long secret-like tokens', () => {
    const { value } = redactText(
      'contact admin@corp.internal key AKIAIOSFODNN7EXAMPLELONGENOUGH123456',
    );
    expect(value).toContain('[REDACTED-EMAIL]');
    expect(value).toContain('[REDACTED-SECRET]');
  });

  it('scrubs the internal IP hiding in the demo cookie evidence', () => {
    const { value, total } = redactFindings(findings);
    const cookie = value.find((f) => f.id === 'cookie:sessionid')!;
    expect(cookie.evidence).not.toContain('10.0.14.22');
    expect(total).toBeGreaterThan(0);
  });

  it('leaves finding structure intact', () => {
    const { value } = redactFindings(findings);
    expect(value).toHaveLength(findings.length);
    expect(value[0].id).toBe(findings[0].id);
  });
});

describe('advisor pipeline — end to end', () => {
  it('produces a full grounded report from the demo findings', async () => {
    const report = await analyze(findings, mockAdvisor);

    expect(report.riskScore).toBeGreaterThan(0);
    expect(report.riskScore).toBeLessThanOrEqual(100);
    expect(report.assessments).toHaveLength(findings.length);
    expect(report.executiveSummary.length).toBeGreaterThan(0);
    expect(report.meta.groundedCount).toBeGreaterThan(0);
    expect(report.meta.provider).toBe('mock');
  });

  it('ranks critical findings first', () => {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    return analyze(findings, mockAdvisor).then((report) => {
      const indices = report.assessments.map((a) => order.indexOf(a.severity));
      const sorted = [...indices].sort((a, b) => a - b);
      expect(indices).toEqual(sorted);
    });
  });

  it('grounded assessments carry a citation, ungrounded do not', async () => {
    const report = await analyze(findings, mockAdvisor);
    for (const a of report.assessments) {
      if (a.grounded) expect(a.reference).toMatch(/^https?:\/\//);
      else expect(a.reference).toBeNull();
    }
  });

  it('a critical finding pushes the risk score high', async () => {
    const report = await analyze(findings, mockAdvisor);
    // Demo set contains a critical (AWS key), so score should be serious.
    expect(report.riskScore).toBeGreaterThanOrEqual(50);
  });

  it('grounding never downgrades a finding below the engine severity', async () => {
    // The AWS-key finding is critical in the engine but the KB entry is "high".
    // The assessment must keep the worse of the two: critical.
    const report = await analyze(findings, mockAdvisor);
    const awsKey = report.assessments.find((a) => a.findingId.startsWith('secret:'))!;
    expect(awsKey.severity).toBe('critical');
  });
});

describe('schema — validates and repairs model output (build-day reliability)', () => {
  const good = JSON.stringify({
    riskScore: 72,
    executiveSummary: 'One critical issue to fix today.',
    assessments: [
      {
        findingId: 'secret:aws',
        title: 'AWS key exposed',
        severity: 'critical',
        businessImpact: 'Anyone can use your cloud account.',
        remediation: ['Rotate the key now.'],
      },
    ],
  });

  it('accepts a well-formed report', () => {
    const result = parseReport(good);
    expect(result.ok).toBe(true);
  });

  it('accepts a report wrapped in a ```json fence with prose around it', () => {
    const wrapped = 'Sure! Here is the JSON:\n```json\n' + good + '\n```\nHope that helps.';
    const result = parseReport(wrapped);
    expect(result.ok).toBe(true);
  });

  it('rejects malformed JSON with an error message (drives the repair retry)', () => {
    const result = parseReport('{ this is not json ');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.length).toBeGreaterThan(0);
  });

  it('rejects a valid-JSON but wrong-shape response', () => {
    const result = parseReport(JSON.stringify({ riskScore: 999, assessments: 'nope' }));
    expect(result.ok).toBe(false);
  });
});
