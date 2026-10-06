import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';

const require = createRequire(import.meta.url);
const { createReadOnlyTools } = require('../desktop-app/mcp/read-only-tools.js');

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

function readVersion() {
  try {
    return fs.readFileSync(path.join(root, 'VERSION'), 'utf8').trim() || '0.0.0';
  } catch (_) {
    return '0.0.0';
  }
}

function asToolResult(value) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(value, null, 2),
      },
    ],
  };
}

const annotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

serveStdio(() => {
  const tools = createReadOnlyTools();
  const server = new McpServer({
    name: 'malguard-local',
    version: readVersion(),
    description: 'Read-only MalGuard local status, sandbox health, and redacted diagnostics. No arbitrary shell or file access.',
  });

  server.registerTool(
    'get_malguard_status',
    {
      description: 'Read a privacy-bounded snapshot of the local MalGuard service status.',
      annotations,
    },
    async () => asToolResult(await tools.getMalguardStatus()),
  );

  server.registerTool(
    'get_sandbox_health',
    {
      description: 'Read the existing MalGuard sandbox certification state without launching a sample or changing system state.',
      annotations,
    },
    async () => asToolResult(await tools.getSandboxHealth()),
  );

  server.registerTool(
    'get_recent_logs',
    {
      description: 'Read up to 20 recent MalGuard diagnostic reports after path/secret redaction. Stacks and environment variables are excluded.',
      annotations,
    },
    async () => asToolResult(await tools.getRecentLogs()),
  );

  return server;
});
