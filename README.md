# Claude Skill Guard: security scanner for Claude Code skills and plugins

[![CI](https://github.com/tauseefahmad/claude-skill-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/tauseefahmad/claude-skill-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Node 18+](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
![No dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

**Check Claude Code skills and plugins for malware before you install them.** skill-guard scans every skill
for prompt injection, hidden instructions, API-key and credential theft, data exfiltration, remote code
execution and malicious hooks, blocks the dangerous ones automatically, and explains every finding in
plain language.

A skill is instructions the AI agent follows plus scripts that run with **your** permissions. That makes
skills an easy place to hide a prompt injection, a key stealer or a backdoor inside something that looks
like a "PDF helper". skill-guard reads them before they can do anything.

**Website:** https://tauseefahmad.github.io/claude-skill-guard/

```
  you / the agent installs a skill
              │
              ▼
  ┌───────────────────────┐   DANGEROUS / SUSPICIOUS → blocked, with the reason
  │ 1. Pre-install check  │   download straight into the skills folder → blocked
  └───────────┬───────────┘   CLEAN / REVIEW → allowed, with a summary
              ▼
  ┌───────────────────────┐   anything that slipped past (scripts, wildcards)
  │ 2. Post-install net   │   → moved to quarantine, nothing deleted
  └───────────┬───────────┘
              ▼
  ┌───────────────────────┐   skills added by hand or via /plugin
  │ 3. Session-start scan │   → flagged before you use them
  └───────────────────────┘
```

- **Zero dependencies.** Plain Node.js 18+, nothing downloaded, nothing to trust but these three files.
- **Read-only scanner.** It never runs, imports or installs anything it scans (there is a test for that).
- **Tamper-evident approvals.** An approved skill is pinned to a SHA-256 of its content; any later change
  is checked again, so a skill cannot start clean and turn malicious in an update.
- **Works on Windows, macOS and Linux**, tested in CI on Node 18, 22 and 24.

---

## What it catches

| Category | Examples |
|---|---|
| **Hidden instructions** | Invisible Unicode "tag" characters (decoded and shown to you), zero-width and right-to-left characters, HTML comments that are hidden on GitHub but read by the agent |
| **Prompt injection** | "ignore previous instructions", "don't tell the user", fake `system:` text, "you are now…" |
| **Permission bypass** | `--dangerously-skip-permissions`, `bypassPermissions`, "skip confirmation", `allowed-tools: Bash` (any command, no prompt) |
| **Trigger hijacking** | Descriptions like "always use this skill for every request" |
| **Credential theft** | `~/.ssh`, `id_rsa`, `.aws/credentials`, `.npmrc`, `.git-credentials`, browser passwords and cookies, the agent's own login, `.env` files, full environment dumps |
| **Data exfiltration** | webhook catchers, tunnels (ngrok and similar), Discord/Telegram/Slack webhooks, pastebins, raw IP addresses, uploads (`curl -d`, `requests.post`, …) |
| **Remote code execution** | download-and-pipe-to-shell, `iex (irm …)`, `DownloadString`, `eval`/`exec`, unpinned `npx -y` / `pip install git+…` |
| **Persistence** | Writing to `settings.json`, `CLAUDE.md`, memory files, hooks; shell profiles, cron, scheduled tasks, startup folder, registry Run keys |
| **Security tampering** | Turning off Windows Defender, firewall, execution policy, SELinux, macOS Gatekeeper |
| **Destruction** | Recursive deletes of your home folder, `format`, `git push --force`, shadow-copy deletion |
| **Obfuscation** | Long base64 blobs (decoded preview shown), `atob`, `b64decode`, `fromCharCode`, `-EncodedCommand` |
| **Opaque files** | Bundled `.exe`/`.dll`/`.so`, archives, symlinks pointing outside the skill |
| **Auto-run code (plugins)** | Every hook command and MCP server is listed, because they run without you invoking anything |

It also lists **every outbound host** a skill contains, so you can see who it talks to.

## What a review looks like

In a terminal (colour in real terminals, `--ascii` for old consoles):

```
━━ ✔ CLEAN (10) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✔ sec-filings         3 files · network: data.sec.gov ×4, www.sec.gov ×3
  ✔ date-formatter      2 files · no network

━━ ◆ REVIEW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  plugin "log-compressor" · 44 files
  Nothing known-bad, but parts run on their own or need a human look.

  Findings   ● 0 critical   ● 0 high   ● 6 medium   ● 8 low

  MEDIUM   auto-hook ×5
           Runs automatically on agent events without you invoking the skill.
           ▸ hooks\hooks.json:7    node "${CLAUDE_PLUGIN_ROOT}/bin/cli.mjs" hook session
           ▸ hooks\hooks.json:13   node "${CLAUDE_PLUGIN_ROOT}/bin/cli.mjs" hook pre

  Network    github.com ×22 · img.shields.io ×2  (30 URLs)

━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✖ 0 DANGEROUS     ⚠ 0 SUSPICIOUS     ◆ 2 REVIEW     ✔ 11 CLEAN
```

When you ask for a full audit, the agent also reads every file and gives a plain-language verdict,
🟢 **SAFE**, 🟡 **CAUTION** or 🔴 **DO NOT INSTALL**, with an at-a-glance checklist (network, auto-run code,
secrets, writes, hidden text) and a findings table. That review checks whether the code really does what
its description says, follows your data to the network, and looks for delayed or conditional behaviour that
patterns cannot see.

| Scanner verdict | Meaning |
|---|---|
| `✖ DANGEROUS` | Critical pattern (hidden text, pipe-to-shell, known exfiltration endpoint, security tampering). Blocked. |
| `⚠ SUSPICIOUS` | High-risk pattern (secret access, config writes, injection phrases). Blocked. |
| `◆ REVIEW` | Worth a look (uploads, auto-run hooks, decoding). Allowed, and flagged. |
| `✔ CLEAN` | Nothing matched. Allowed. |

---

## Install

Requires **Node.js 18+**. No dependencies.

**1. Copy the skill**

```bash
git clone https://github.com/tauseefahmad/claude-skill-guard.git
cp -r claude-skill-guard/skill-guard ~/.claude/skills/            # macOS / Linux
```

```powershell
Copy-Item -Recurse claude-skill-guard\skill-guard $HOME\.claude\skills\   # Windows
```

Copy only the `skill-guard` folder, not the whole repository.

**2. Add the hooks** to `~/.claude/settings.json` (merge with hooks you already have). Use the absolute
path to your home folder, e.g. `/Users/you` or `C:/Users/you`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "node \"/ABSOLUTE/HOME/.claude/skills/skill-guard/guard-hook.mjs\" pre", "timeout": 60 }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [{ "type": "command", "command": "node \"/ABSOLUTE/HOME/.claude/skills/skill-guard/guard-hook.mjs\" post", "timeout": 60 }]
      }
    ],
    "SessionStart": [
      {
        "hooks": [{ "type": "command", "command": "node \"/ABSOLUTE/HOME/.claude/skills/skill-guard/guard-hook.mjs\" session", "timeout": 60 }]
      }
    ]
  }
}
```

**3. Record what you already have** as your starting point, so the first session does not flag everything:

```bash
node ~/.claude/skills/skill-guard/scan.mjs                         # look at the results first
node ~/.claude/skills/skill-guard/scan.mjs --accept <each skill you trust>
```

Skills the scanner marks CLEAN are recorded automatically at the next session start.

**Uninstall:** remove the three hook entries from `settings.json`, then delete
`~/.claude/skills/skill-guard/` and `~/.claude/skill-guard/`.

## Use it

Just ask in the chat:

| Say | What happens |
|---|---|
| "Is this skill safe? https://github.com/someone/cool-skill" | Cloned into a scratch folder (git hooks disabled), scanned and fully reviewed. Nothing is installed. |
| "Install this skill: …" | Checked automatically before it lands. |
| "Audit my skills" | Every installed skill and plugin is checked. |
| "What changed in my skills?" | Only skills that are new or changed since you last approved them. |
| "Install it anyway" | After a block, records that exact version as approved and retries. |

Or run the scanner yourself, for example in CI for a skills repository:

```bash
node skill-guard/scan.mjs                       # everything installed
node skill-guard/scan.mjs ./some-skill          # one folder (or a folder of skills)
node skill-guard/scan.mjs --changed             # only new/changed since last approval
node skill-guard/scan.mjs --accept ./some-skill # approve this exact version
node skill-guard/scan.mjs --json                # machine-readable output
```

Exit codes: `0` clean/review, `1` suspicious, `2` dangerous, `3` usage error.

Quarantined skills are moved, not deleted, to `~/.claude/skill-guard/quarantine/<name>-<timestamp>`. To
restore one you trust, `--accept` it, then move the folder back into `~/.claude/skills/<name>`.

---

## FAQ

**Are Claude Code skills safe?**
Most are. But a skill runs with your permissions and its instructions are followed by the agent, so a
malicious one can read your files and keys, send them anywhere, or change your settings. Treat a skill like
any other code you install: check it first.

**How do I check a Claude skill for malware?**
Install skill-guard and ask "Is this skill safe?" with the link, before installing. It clones the skill into a
scratch folder with git hooks disabled, scans it and reviews every file. Or run `scan.mjs` on the folder.

**Does it work with Claude Code plugins and MCP servers?**
Yes. Plugins are scanned like skills, and every hook command and MCP server they declare is listed, because
those run without you invoking anything.

**Does it send my code anywhere?**
No. The scanner is local and read-only, makes no network requests and has no dependencies.

**Why does skill-guard flag itself as DANGEROUS when I scan its folder?**
Its rule list contains the attack strings it looks for. Installed in its own folder it skips itself.

**Is a CLEAN result a guarantee?**
No. Pattern matching catches known tricks; a careful attacker can write something new. The full audit covers
much more, but a clean result still means "nothing found", not "proven safe".

## Limits

- **Expect some false positives.** Plenty of legitimate skills send data or launch programs. REVIEW means
  "look", not "bad".
- **The `/plugin` menu and manual copies** cannot be stopped beforehand, because the agent is not involved.
  They are flagged at the next session start, before you would normally use them.
- **Binaries and archives inside a skill** cannot be reviewed by reading. They are always flagged.
- **skill-guard trusts its own folder**, so it can be edited and fixed. Keep it somewhere only you write to.
- **Static review only.** It does not sandbox or monitor skills while they run.

If something is flagged after it already ran, rotate any keys or tokens it could reach, then check
`settings.json`, `CLAUDE.md`, your memory files, shell profiles and scheduled tasks for anything it added.

## Files

| Path | What it is |
|---|---|
| `skill-guard/SKILL.md` | The audit procedure the agent follows (untrusted-data rules, review checklist, report format) |
| `skill-guard/scan.mjs` | Static scanner. Read-only: never runs, imports or installs anything it scans |
| `skill-guard/guard-hook.mjs` | The three hooks (`pre`, `post`, `session`) |
| `test/` | Tests; the fake malicious skills are generated at test time, none are stored here |

## License

MIT
