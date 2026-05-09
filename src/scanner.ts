/**
 * Pure scanner: regex-based detectors plus a Shannon-entropy fallback.
 * No I/O. The MCP server in `server.ts` provides the file/text wrappers.
 *
 * Detectors mirror the Rust `secretsniff-core` set so behavior is
 * consistent across language ports.
 */

export interface ScannerOptions {
  /** Shannon-entropy threshold (bits/char). 4.5 is a reasonable default. */
  minEntropy: number;
  /** Minimum substring length (chars) for the high-entropy fallback rule. */
  minEntropyLength: number;
  /** When false, skip the high-entropy rule entirely. */
  includeHighEntropy: boolean;
}

export interface Finding {
  /** Detector name (e.g. `AWS_ACCESS_KEY`). */
  kind: string;
  /** 1-indexed line number. */
  line: number;
  /** 1-indexed byte offset within the line. */
  column: number;
  /** Byte offset of the match start in the source. */
  start: number;
  /** Byte offset (exclusive) of the match end. */
  end: number;
  /** The matched substring. */
  matched: string;
  /** Shannon entropy in bits/char of the matched string. */
  entropy: number;
}

const RULES: ReadonlyArray<readonly [string, RegExp]> = [
  ['AWS_ACCESS_KEY', /\bAKIA[0-9A-Z]{16}\b/g],
  // GitHub token formats: ghp_/gho_/ghu_/ghr_/ghs_.
  ['GITHUB_TOKEN', /\bgh[pours]_[A-Za-z0-9]{36,}\b/g],
  ['SLACK_TOKEN', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g],
  // Stripe live/test keys (sk/pk/rk).
  ['STRIPE_KEY', /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g],
  // JWT: three url-safe-base64 segments separated by `.`.
  ['JWT', /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g],
  // PEM-style markers.
  ['RSA_PRIVATE_KEY', /-----BEGIN RSA PRIVATE KEY-----/g],
  ['SSH_PRIVATE_KEY', /-----BEGIN OPENSSH PRIVATE KEY-----/g],
  // Generic api_key = "..." assignments.
  ['GENERIC_API_KEY', /\bapi[_-]?key\s*[=:]\s*['"]([A-Za-z0-9_\-=]{16,})['"]/gi],
];

/**
 * Scan a string and return findings ordered by their byte position.
 */
export function scanText(text: string, opts: ScannerOptions): Finding[] {
  if (opts.minEntropy < 0 || opts.minEntropy > 8) {
    throw new Error(`min_entropy out of range [0, 8]: ${opts.minEntropy}`);
  }
  const findings: Finding[] = [];
  const covered: Array<[number, number]> = [];

  // Apply each rule.
  for (const [kind, regex] of RULES) {
    // Reset lastIndex because we mutate global state across calls when reusing
    // the module-level regex. Cloning into a fresh regex is safer.
    const re = new RegExp(regex.source, regex.flags);
    for (const m of text.matchAll(re)) {
      const start = m.index ?? 0;
      const end = start + m[0].length;
      const { line, column } = lineCol(text, start);
      findings.push({
        kind,
        line,
        column,
        start,
        end,
        matched: m[0],
        entropy: shannonEntropy(m[0]),
      });
      covered.push([start, end]);
    }
  }

  // High-entropy fallback. Skip ranges that overlap a known-pattern hit.
  if (opts.includeHighEntropy) {
    const len = Math.max(opts.minEntropyLength, 1);
    const heRe = new RegExp(`[A-Za-z0-9+/=_\\-]{${len},}`, 'g');
    for (const m of text.matchAll(heRe)) {
      const start = m.index ?? 0;
      const end = start + m[0].length;
      if (overlapsAny(covered, start, end)) continue;
      const e = shannonEntropy(m[0]);
      if (e < opts.minEntropy) continue;
      const { line, column } = lineCol(text, start);
      findings.push({
        kind: 'HIGH_ENTROPY',
        line,
        column,
        start,
        end,
        matched: m[0],
        entropy: e,
      });
    }
  }

  findings.sort((a, b) => a.start - b.start);
  return findings;
}

// --- helpers --------------------------------------------------------------

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<number, number>();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  const n = s.length;
  let e = 0;
  for (const c of counts.values()) {
    const p = c / n;
    e -= p * Math.log2(p);
  }
  return e;
}

function lineCol(source: string, byteOffset: number): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < byteOffset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10 /* \n */) {
      line += 1;
      lastNewline = i;
    }
  }
  // column is 1-indexed offset within the line; +1 because the position
  // immediately after the last newline is column 1.
  return { line, column: byteOffset - lastNewline };
}

function overlapsAny(ranges: ReadonlyArray<readonly [number, number]>, start: number, end: number): boolean {
  for (const [s, e] of ranges) {
    if (start < e && end > s) return true;
  }
  return false;
}
