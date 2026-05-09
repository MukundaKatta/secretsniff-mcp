# secretsniff-mcp

[![npm](https://img.shields.io/npm/v/@mukundakatta/secretsniff-mcp.svg)](https://www.npmjs.com/package/@mukundakatta/secretsniff-mcp)
[![mcp](https://img.shields.io/badge/protocol-MCP-blue.svg)](https://modelcontextprotocol.io)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An [MCP](https://modelcontextprotocol.io) server that gives AI assistants
the ability to scan text or code for accidentally-committed secrets before
they ship.

Works with Claude Desktop, Cursor, Cline, Windsurf, Zed, and any other MCP
client.

## What it catches

| Detector | Pattern |
|---|---|
| `AWS_ACCESS_KEY` | `AKIA…` 20-char keys |
| `GITHUB_TOKEN` | `ghp_/gho_/ghu_/ghr_/ghs_…` |
| `SLACK_TOKEN` | `xox[baprs]-…` |
| `STRIPE_KEY` | `sk_live_/sk_test_/pk_live_/pk_test_…` |
| `JWT` | three url-safe base64 segments |
| `RSA_PRIVATE_KEY` | `-----BEGIN RSA PRIVATE KEY-----` marker |
| `SSH_PRIVATE_KEY` | `-----BEGIN OPENSSH PRIVATE KEY-----` marker |
| `GENERIC_API_KEY` | `api[_-]?key\s*[=:]\s*"…"` style assignments |
| `HIGH_ENTROPY` | strings ≥ 32 chars with Shannon entropy ≥ 4.5 bits/char |

## Tools exposed

### `scan_text`

Scan a string for secrets. Returns one entry per finding with line/column,
the matched substring, and Shannon entropy.

```json
{ "text": "const KEY = 'AKIAIOSFODNN7EXAMPLE';" }
```

→

```json
{
  "findings": [
    {
      "kind": "AWS_ACCESS_KEY",
      "line": 1,
      "column": 14,
      "start": 13,
      "end": 33,
      "matched": "AKIAIOSFODNN7EXAMPLE",
      "entropy": 3.78
    }
  ]
}
```

### `scan_file`

Read a file from disk and scan it. Same return shape as `scan_text` plus
the file path. Useful when an agent has just written a file and wants to
double-check it before committing.

## Configure your MCP client

Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secretsniff": {
      "command": "npx",
      "args": ["-y", "@mukundakatta/secretsniff-mcp"]
    }
  }
}
```

Cursor / Cline / Windsurf / Zed configs follow the same `command` + `args`
pattern.

## Why this is not a `--lint` flag

This is meant for the **agentic** loop: an LLM that just wrote a config or
edited a file calls `scan_text` on its own output before declaring success.
Existing CLI scanners (`gitleaks`, `trufflehog`) target the
human-driven pre-commit workflow; they're great at that and I'd still run
them in CI. `secretsniff-mcp` covers the gap during the LLM's editing turn.

## License

MIT.
