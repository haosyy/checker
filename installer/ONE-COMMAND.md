# One-command voluntary checks

Deploy once from discord-relay with `npx wrangler deploy`. Keep the existing REPORT_API_TOKEN and DISCORD_WEBHOOK secrets. The new CheckSession SQLite Durable Object binding and migration are in wrangler.toml. Deployment may allocate billable Cloudflare resources according to the account plan. GitHub commits do not deploy Cloudflare.

The existing GUI EXE using snake_case reports does not need rebuilding.

Administrator: run installer/new-check.ps1 with -ExpectedSha256 (the trusted ZIP hash) and -LauncherCommit (the full Git commit containing the launcher). Enter the administrator secret only on the administrator computer. Send the generated command to one player.

Player: paste that command into PowerShell, approve UAC and wait for the automatic GUI check. No token prompt. PowerShell script execution must be permitted by the machine policy; this launcher does not override policy.

Codes are bearer credentials: anyone who gets a code can submit its one permitted report. Valid for one hour from creation. The command and process arguments expose only that limited code, never the administrator secret. The server consumes the code atomically before forwarding to Discord; if delivery fails, create a fresh command. This prevents duplicate forwarding, but does not guarantee delivery. Close the checker only after the report delivery result is displayed.

This authorizes report submission; it does not attest that the client or its findings are genuine. Existing administrator-token reports continue to work. The existing report renderer and Discord webhook are unchanged. Detection rules are not expanded by this change.
