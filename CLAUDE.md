@AGENTS.md

## Keep the MCP server (and CLI) in sync

This repo exposes three entrypoints over one scanner core (`src/lib/scanner/`): the web app, the CLI (`bin/vantasec-scan.mjs`), and the **MCP server** (`bin/vantasec-mcp.mjs`). Whenever you add or change a scanner check or its result shape, update the MCP server in the same change so its output stays current:

- Reflect new findings in the MCP report (`formatReport`) and the "what's set up well" list (`computeStrengths`) in `bin/vantasec-mcp.mjs`; extend `SCAN_OUTPUT_SCHEMA` / `structuredContent` if you add machine-readable fields.
- Keep the CLI summary (`bin/vantasec-scan.mjs`) consistent with it.
- After editing, smoke-test: `printf '<initialize>\n<tools/call scan>\n' | node bin/vantasec-mcp.mjs` (or just `npm run mcp`). The server is registered user-scope and reloads on the next Claude Code restart — no re-register needed.
