#!/usr/bin/env node
/**
 * secretsniff MCP server.
 *
 * Exposes two tools to any MCP client (Claude Desktop, Cursor, Cline,
 * Windsurf, Zed, etc.):
 *
 *   scan_text  — scan an in-memory string for accidentally-committed secrets
 *   scan_file  — read a file from disk and scan it
 *
 * Detectors cover the high-frequency leak surfaces (AWS access keys,
 * GitHub tokens, Slack tokens, Stripe keys, JWTs, RSA/SSH private key
 * markers, generic `api_key = "..."` assignments) plus a Shannon-entropy
 * fallback for everything else.
 *
 * Configure your client to spawn this binary over stdio. Example for
 * Claude Desktop's `claude_desktop_config.json`:
 *
 *   {
 *     "mcpServers": {
 *       "secretsniff": {
 *         "command": "npx",
 *         "args": ["-y", "@mukundakatta/secretsniff-mcp"]
 *       }
 *     }
 *   }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { readFile } from 'node:fs/promises';

import { type Finding, type ScannerOptions, scanText } from './scanner.js';

const VERSION = '0.1.0';

const server = new Server(
  {
    name: 'secretsniff',
    version: VERSION,
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

// --- tool catalog ---------------------------------------------------------

const TOOLS = [
  {
    name: 'scan_text',
    description:
      'Scan a string for accidentally-committed secrets. Returns one finding per match with kind (AWS_ACCESS_KEY, GITHUB_TOKEN, etc.), line/column, byte offsets, the matched substring, and Shannon entropy.',
    inputSchema: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'Text to scan (any size).',
        },
        min_entropy: {
          type: 'number',
          description:
            'Shannon-entropy threshold (bits/char) for the high-entropy fallback rule. Default 4.5.',
          default: 4.5,
        },
        min_entropy_length: {
          type: 'integer',
          description:
            'Minimum substring length (chars) for the high-entropy rule. Default 32.',
          default: 32,
        },
        include_high_entropy: {
          type: 'boolean',
          description:
            'When false, skip the high-entropy rule entirely. Default true.',
          default: true,
        },
      },
      required: ['text'],
    },
  },
  {
    name: 'scan_file',
    description:
      'Read a file from disk and scan it. Same return shape as scan_text plus the file path. Use when the agent has just written or edited a file and wants to double-check before declaring success.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Absolute or relative path to the file to scan.',
        },
        min_entropy: { type: 'number', default: 4.5 },
        min_entropy_length: { type: 'integer', default: 32 },
        include_high_entropy: { type: 'boolean', default: true },
      },
      required: ['path'],
    },
  },
] as const;

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

// --- tool dispatch --------------------------------------------------------

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;

  try {
    switch (name) {
      case 'scan_text':
        return scanTextTool(args as unknown as ScanTextArgs);
      case 'scan_file':
        return await scanFileTool(args as unknown as ScanFileArgs);
      default:
        return errorResult('unknown tool: ' + name);
    }
  } catch (err) {
    return errorResult('internal error: ' + (err as Error).message);
  }
});

// --- tool implementations -------------------------------------------------

interface ScanTextArgs {
  text: string;
  min_entropy?: number;
  min_entropy_length?: number;
  include_high_entropy?: boolean;
}

interface ScanFileArgs {
  path: string;
  min_entropy?: number;
  min_entropy_length?: number;
  include_high_entropy?: boolean;
}

function optionsFrom(args: ScanTextArgs | ScanFileArgs): ScannerOptions {
  return {
    minEntropy: args.min_entropy ?? 4.5,
    minEntropyLength: args.min_entropy_length ?? 32,
    includeHighEntropy: args.include_high_entropy ?? true,
  };
}

function scanTextTool(args: ScanTextArgs) {
  const findings = scanText(args.text, optionsFrom(args));
  return findingsResult(findings);
}

async function scanFileTool(args: ScanFileArgs) {
  const text = await readFile(args.path, 'utf8');
  const findings = scanText(text, optionsFrom(args));
  return findingsResult(findings, args.path);
}

function findingsResult(findings: Finding[], path?: string) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            ...(path !== undefined ? { path } : {}),
            count: findings.length,
            findings,
          },
          null,
          2,
        ),
      },
    ],
  };
}

function errorResult(message: string) {
  return {
    isError: true,
    content: [{ type: 'text', text: message }],
  };
}

// --- bootstrap ------------------------------------------------------------

const transport = new StdioServerTransport();
await server.connect(transport);

process.stderr.write(`secretsniff MCP server v${VERSION} ready on stdio\n`);
