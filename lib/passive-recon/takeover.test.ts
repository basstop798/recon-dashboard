import { describe, it, expect } from 'vitest';
import { fingerprintCname, classifyResolution, TAKEOVER_FINGERPRINTS } from './takeover';

/**
 * These tests exist because `takeover.ts` decides a `high`-severity,
 * `takeover: true` finding — the kind a bug-bounty hunter files with a
 * program. A false positive there costs reputation, so the negative cases
 * ("this is NOT a takeover") matter at least as much as the positive ones and
 * get the most coverage below.
 */

describe('fingerprintCname — anchored identification', () => {
  it('identifies providers from real endpoint hostnames', () => {
    const cases: [string, string][] = [
      ['myapp.herokuapp.com', 'Heroku'],
      ['myapp.herokudns.com', 'Heroku'],
      ['docs.github.io', 'GitHub Pages'],
      ['site.bitbucket.io', 'Bitbucket'],
      ['app.azurewebsites.net', 'Azure'],
      ['thing.elasticbeanstalk.com', 'AWS Elastic Beanstalk'],
      ['bucket.s3.amazonaws.com', 'AWS S3'],
    ];
    for (const [cname, service] of cases) {
      expect(fingerprintCname(cname)?.service, cname).toBe(service);
    }
  });

  it('matches the apex itself, not only subdomains of it', () => {
    expect(fingerprintCname('herokuapp.com')?.service).toBe('Heroku');
    expect(fingerprintCname('github.io')?.service).toBe('GitHub Pages');
  });

  it('ignores case, surrounding space and a trailing root dot from DNS', () => {
    expect(fingerprintCname('MyApp.HerokuApp.Com')?.service).toBe('Heroku');
    expect(fingerprintCname('myapp.herokuapp.com.')?.service).toBe('Heroku');
    expect(fingerprintCname('  myapp.herokuapp.com  ')?.service).toBe('Heroku');
  });

  it('returns null for an empty or unrecognised target', () => {
    expect(fingerprintCname('')).toBeNull();
    expect(fingerprintCname('   ')).toBeNull();
    expect(fingerprintCname('.')).toBeNull();
    expect(fingerprintCname('example.com')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The regression that motivated this file.
//
// Identification used to accept `target.includes(suffix)`, so any hostname
// CONTAINING a provider's domain was attributed to that provider — including
// hostnames owned by somebody else entirely.
// ---------------------------------------------------------------------------
describe('fingerprintCname — never attributes a provider it does not own (regression)', () => {
  const impostors = [
    // Provider domain on the LEFT; the real owner is the last two labels.
    'github.io.attacker-controlled.com',
    'herokuapp.com.attacker-controlled.com',
    'azurewebsites.net.phish.ru',
    's3.amazonaws.com.evil.net',
    'bitbucket.io.not-bitbucket.org',
    // Provider domain embedded in a longer label.
    'notgithub.io',
    'my-herokuapp.com',
    'fake-azurewebsites.net.example.com',
    // A private hostname that merely contains ".s3." or "s3-website".
    'cdn.s3.mycompany.internal',
    's3-website.internal.example.com',
  ];

  for (const cname of impostors) {
    it(`does not attribute a provider to "${cname}"`, () => {
      expect(fingerprintCname(cname)).toBeNull();
    });
  }

  it('does not escalate a dangling CNAME on a look-alike host to a takeover', () => {
    const result = classifyResolution({
      host: 'www.example.com',
      addresses: [],
      cname: 'github.io.attacker-controlled.com',
      resolves: false,
    });
    // Still reported — the delegation really is broken — but as an unknown
    // target, not as a confirmed GitHub Pages takeover at high severity.
    expect(result.status).toBe('dangling');
    expect(result.takeover).toBe(false);
    expect(result.severity).toBe('medium');
    expect(result.service).toBeNull();
    expect(result.note).not.toContain('GitHub');
  });
});

// ---------------------------------------------------------------------------
// AWS shares one apex across every service, so S3 needs a label marker.
// ---------------------------------------------------------------------------
describe('fingerprintCname — AWS S3 endpoint forms', () => {
  it('recognises the global, regional and website endpoint forms', () => {
    const s3Hosts = [
      'bucket.s3.amazonaws.com',
      'bucket.s3.us-east-1.amazonaws.com',
      'bucket.s3-website-us-east-1.amazonaws.com',
      'bucket.s3-website.us-east-1.amazonaws.com',
      'bucket.s3-eu-west-1.amazonaws.com',
    ];
    for (const host of s3Hosts) {
      expect(fingerprintCname(host)?.service, host).toBe('AWS S3');
    }
  });

  it('does not claim non-S3 AWS hostnames as S3', () => {
    // Same apex, different service: the s3 label is absent, so the S3
    // fingerprint must decline rather than swallow all of AWS.
    const notS3 = [
      'ec2-203-0-113-25.compute-1.amazonaws.com',
      'queue.sqs.us-east-1.amazonaws.com',
      'something.execute-api.us-east-1.amazonaws.com',
    ];
    for (const host of notS3) {
      expect(fingerprintCname(host)?.service, host).not.toBe('AWS S3');
    }
  });

  it('does not treat a bucket-ish label outside AWS as S3', () => {
    expect(fingerprintCname('s3.mycompany.com')).toBeNull();
    expect(fingerprintCname('s3-website.example.org')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// classifyResolution: the severity and note actually shown to the operator.
// ---------------------------------------------------------------------------
describe('classifyResolution', () => {
  it('reports a dangling CNAME at a confirmed provider as high severity', () => {
    const result = classifyResolution({
      host: 'old.example.com',
      addresses: [],
      cname: 'ghost-app.herokuapp.com',
      resolves: false,
    });
    expect(result.status).toBe('dangling');
    expect(result.takeover).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.service).toBe('Heroku');
  });

  it('reports a dangling CNAME at an edge-case provider as medium severity', () => {
    const result = classifyResolution({
      host: 'old.example.com',
      addresses: [],
      cname: 'env.elasticbeanstalk.com',
      resolves: false,
    });
    expect(result.takeover).toBe(true);
    expect(result.severity).toBe('medium');
    expect(result.service).toBe('AWS Elastic Beanstalk');
  });

  it('reports a dangling CNAME at an unknown target as medium, not a takeover', () => {
    const result = classifyResolution({
      host: 'old.example.com',
      addresses: [],
      cname: 'gone.some-small-host.net',
      resolves: false,
    });
    expect(result.status).toBe('dangling');
    expect(result.takeover).toBe(false);
    expect(result.severity).toBe('medium');
    expect(result.service).toBeNull();
  });

  it('never reports a takeover for a host that still resolves', () => {
    const result = classifyResolution({
      host: 'live.example.com',
      addresses: ['203.0.113.10'],
      cname: 'live-app.herokuapp.com',
      resolves: true,
    });
    expect(result.status).toBe('live');
    expect(result.takeover).toBe(false);
    expect(result.severity).toBe('info');
    expect(result.service).toBe('Heroku');
  });

  it('treats a non-resolving host with no CNAME as nxdomain, not a takeover', () => {
    const result = classifyResolution({
      host: 'gone.example.com',
      addresses: [],
      cname: null,
      resolves: false,
    });
    expect(result.status).toBe('nxdomain');
    expect(result.takeover).toBe(false);
    expect(result.severity).toBe('info');
  });

  it('describes a live host with no recognised provider plainly', () => {
    const direct = classifyResolution({
      host: 'example.com',
      addresses: ['203.0.113.1'],
      cname: null,
      resolves: true,
    });
    expect(direct.status).toBe('live');
    expect(direct.service).toBeNull();
    expect(direct.note).toBe('Resolves directly.');

    const aliased = classifyResolution({
      host: 'www.example.com',
      addresses: ['203.0.113.1'],
      cname: 'internal.example.net',
      resolves: true,
    });
    expect(aliased.note).toContain('internal.example.net');
  });

  it('only ever reports takeover: true together with high or medium severity', () => {
    // Guards the invariant the dashboard relies on when it ranks findings.
    for (const fingerprint of TAKEOVER_FINGERPRINTS) {
      const apex = fingerprint.suffixes[0].replace(/^\.+|\.+$/g, '');
      const label = fingerprint.labelMarkers?.[0] ?? 'probe';
      const result = classifyResolution({
        host: 'probe.example.com',
        addresses: [],
        cname: `probe.${label}.${apex}`,
        resolves: false,
      });
      if (result.takeover) {
        expect(['high', 'medium'], fingerprint.service).toContain(result.severity);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Catalogue integrity.
// ---------------------------------------------------------------------------
describe('TAKEOVER_FINGERPRINTS integrity', () => {
  it('gives every entry a service, a note, a valid status and a suffix', () => {
    for (const f of TAKEOVER_FINGERPRINTS) {
      expect(f.service.length, JSON.stringify(f)).toBeGreaterThan(0);
      expect(f.note.length, f.service).toBeGreaterThan(10);
      expect(f.suffixes.length, f.service).toBeGreaterThan(0);
      expect(['confirmed', 'edge-case', 'not-vulnerable'], f.service).toContain(f.status);
    }
  });

  it('uses only anchored domain suffixes — no bare fragments', () => {
    // A fragment like "s3-website" or ".s3." cannot identify an owner, and
    // allowing one is what produced the false positives above. Anything that
    // needs narrowing belongs in labelMarkers instead.
    for (const f of TAKEOVER_FINGERPRINTS) {
      for (const suffix of f.suffixes) {
        expect(suffix, `${f.service}: "${suffix}"`).toMatch(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/);
      }
    }
  });

  it('does not let two services claim the same unqualified suffix', () => {
    const owner = new Map<string, string>();
    for (const f of TAKEOVER_FINGERPRINTS) {
      // A shared apex is only legitimate when narrowed by labelMarkers.
      if (f.labelMarkers) continue;
      for (const suffix of f.suffixes) {
        const existing = owner.get(suffix);
        expect(existing, `"${suffix}" claimed by ${existing} and ${f.service}`).toBeUndefined();
        owner.set(suffix, f.service);
      }
    }
  });
});
