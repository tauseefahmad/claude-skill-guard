#!/usr/bin/env node
// skill-guard scanner: static triage of Claude skills and plugins.
// Read-only. It never executes, imports or installs anything it scans.
//
//   node scan.mjs                      scan every installed skill + plugin
//   node scan.mjs <path> [<path>...]   scan specific skill/plugin dirs (or a folder of them)
//   node scan.mjs --changed            only units that are new or changed since last --accept
//   node scan.mjs --accept <path|name> record the current hash of a unit as reviewed
//   node scan.mjs --json               machine-readable output
//
// Exit code: 0 clean/review, 1 suspicious, 2 dangerous, 3 usage error.

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

const HOME = os.homedir();
const CLAUDE = path.join(HOME, '.claude');
const SELF_DIR = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const STATE_FILE = path.join(CLAUDE, 'skill-guard', 'state.json');
const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// ---------------------------------------------------------------- rules
// Each rule: id, sev, category, re, files ('md' | 'code' | 'all'), why.
const RULES = [
  // Prompt injection / instruction hijacking (mostly matters in markdown Claude reads)
  { id: 'inject-ignore-instructions', sev: 'high', cat: 'prompt-injection', files: 'all',
    re: /\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|system|safety)\b.{0,20}\b(instructions?|rules|prompts?|guidelines)\b/i,
    why: 'Tries to override Claude\'s existing instructions.' },
  { id: 'inject-hide-from-user', sev: 'high', cat: 'prompt-injection', files: 'all',
    re: /\b(do\s*n[o']t|never|without)\s+(tell(ing)?|inform(ing)?|show(ing)?|mention(ing)?|notify(ing)?|ask(ing)?|alert(ing)?)\s+(the\s+)?(user|human|them)\b/i,
    why: 'Instructs Claude to act behind the user\'s back.' },
  { id: 'inject-silently', sev: 'medium', cat: 'prompt-injection', files: 'md',
    re: /^(?!.*\b(fail|skip|ignor|drop|swallow)\w*\s+(\w+\s+){0,3}silently|.*silently\s+(fail|skip|ignor|drop))(?=.*\b(silently|secretly|covertly|quietly|in the background without)\b)/i,
    why: 'Asks for hidden behaviour; check what is being done silently.' },
  { id: 'inject-role-hijack', sev: 'high', cat: 'prompt-injection', files: 'all',
    re: /(you are now\b|new system prompt|<\/?system>|\[system\]|^\s*system\s*:|developer mode|jailbreak|DAN mode)/im,
    why: 'Fake system/role text used to hijack the model.' },
  { id: 'inject-bypass-permissions', sev: 'critical', cat: 'permission-bypass', files: 'all',
    re: /(dangerously-?skip-?permissions|dangerouslyDisableSandbox|bypassPermissions|--no-verify|skip (the )?(permission|confirmation|approval)|auto-?approve|without (asking|confirmation|approval))/i,
    why: 'Tries to disable Claude Code safety prompts or sandboxing.' },
  { id: 'trigger-hijack', sev: 'medium', cat: 'trigger-hijack', files: 'frontmatter',
    re: /\b(always|every|any|all)\s+(use|invoke|load|run|trigger|request|message|task|conversation|prompt)s?\b/i,
    why: 'Description tries to make the skill fire on everything.' },

  // Remote code execution / supply chain
  { id: 'rce-pipe-to-shell', sev: 'critical', cat: 'remote-code', files: 'all',
    re: /(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b|(curl|wget)\b[^\n|]*\|\s*(python3?|node|perl|ruby|iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+Net\.WebClient|irm|iwr|Invoke-RestMethod|Invoke-WebRequest)/i,
    why: 'Downloads and runs code from the internet in one step.' },
  { id: 'rce-download-exec', sev: 'high', cat: 'remote-code', files: 'all',
    re: /(DownloadString|DownloadFile|urlretrieve|bash\s+<\(\s*curl|sh\s+-c\s+"\$\(curl|python3?\s+-c\s+["'].*urllib)/i,
    why: 'Fetches a remote payload.' },
  { id: 'rce-dynamic-eval', sev: 'medium', cat: 'remote-code', files: 'code',
    re: /\b(eval|exec)\s*\(|new\s+Function\s*\(|\b__import__\s*\(|\bcompile\s*\(.*exec|vm\.runIn|subprocess\.(Popen|call|run)\(.*shell\s*=\s*True|os\.system\s*\(|\bexecSync\s*\(|\bshell\s*:\s*true/,
    why: 'Runs dynamically built code or shell commands; check what gets executed.' },
  { id: 'spawns-processes', sev: 'low', cat: 'remote-code', files: 'code',
    re: /child_process|\bsubprocess\b|Start-Process/,
    why: 'Launches other programs; check which ones.' },
  { id: 'supply-unpinned-install', sev: 'low', cat: 'remote-code', files: 'all',
    re: /\b(npx\s+-y|pip3?\s+install\s+(git\+|https?:)|npm\s+i(nstall)?\s+(-g\s+)?(git\+|https?:|github:))/i,
    why: 'Installs packages straight from a URL or without pinning.' },

  // Secrets / credential access
  { id: 'secret-files', sev: 'high', cat: 'credential-access', files: 'all',
    re: /(\.ssh[\/\\]|id_rsa|id_ed25519|authorized_keys|\.aws[\/\\]credentials|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.docker[\/\\]config\.json|\.kube[\/\\]config|gcloud[\/\\]credentials|Login Data|Cookies\.sqlite|\bcookies\.sqlite|Local State|key4\.db|logins\.json|wallet\.dat|\.gnupg|Keychains?|find-generic-password|credential manager|cmdkey|vaultcmd|\.claude[\/\\]\.credentials|\.claude\.json)/i,
    why: 'Touches credential stores, keys, browser secrets or Claude auth.' },
  { id: 'secret-env-dump', sev: 'high', cat: 'credential-access', files: 'all',
    re: /(\bprintenv\b|\benv\s*\||\bset\s*\|\s*(curl|nc)|Get-ChildItem\s+env:|dict\(os\.environ\)|os\.environ\.copy\(\)|json\.dumps\(\s*os\.environ|JSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|keys)\(\s*process\.env\s*\))/i,
    why: 'Dumps all environment variables (API keys live there).' },
  { id: 'secret-api-keys', sev: 'medium', cat: 'credential-access', files: 'all',
    re: /\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|SLACK_TOKEN|CLAUDE_CODE_OAUTH_TOKEN)\b/,
    why: 'References a high-value secret; check it is not sent anywhere.' },
  { id: 'secret-dotenv', sev: 'medium', cat: 'credential-access', files: 'code',
    re: /['"`][^'"`]*\.env(\.local|\.production)?['"`]/,
    why: 'Reads a .env file.' },

  // Exfiltration channels
  { id: 'exfil-known-sink', sev: 'critical', cat: 'exfiltration', files: 'all',
    re: /(webhook\.site|requestbin|pipedream\.net|hookbin|beeceptor|ngrok(-free)?\.(io|app)|trycloudflare\.com|serveo\.net|localtunnel|interact\.sh|oast\.(fun|pro|live|site)|burpcollaborator|canarytokens|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services|pastebin\.com|paste\.ee|transfer\.sh|0x0\.st|file\.io|temp\.sh)/i,
    why: 'Known data-collection / tunnelling endpoint commonly used for exfiltration.' },
  { id: 'exfil-raw-ip', sev: 'high', cat: 'exfiltration', files: 'all',
    re: /https?:\/\/(?!127\.|0\.0\.0\.0|localhost|10\.|192\.168\.)\d{1,3}(\.\d{1,3}){3}/,
    why: 'Talks to a raw IP address instead of a named service.' },
  { id: 'exfil-dns-or-nc', sev: 'high', cat: 'exfiltration', files: 'all',
    re: /\b(nc|ncat|netcat)\s+(-[a-z]*\s+)*[\w.-]+\s+\d+|\/dev\/tcp\/|nslookup\s+\$|dig\s+\$\(/i,
    why: 'Raw socket / DNS channel often used to leak data.' },
  { id: 'exfil-upload', sev: 'medium', cat: 'exfiltration', files: 'all',
    re: /(requests\.(post|put)\(|httpx\.(post|put)\(|method\s*[:=]\s*['"](POST|PUT)['"]|curl\b[^\n]*\s(-d|--data[\w-]*|-F|--form|-T|--upload-file)\s|Invoke-(WebRequest|RestMethod)\b[^\n]*-Method\s+(Post|Put)|\.sendBeacon\(|XMLHttpRequest)/i,
    why: 'Sends data out; check what is in the payload and where it goes.' },

  // Persistence / tampering with Claude or the OS
  { id: 'persist-claude-config', sev: 'high', cat: 'persistence', files: 'all',
    re: /(?=.*(settings(\.local)?\.json|CLAUDE\.md|MEMORY\.md|AGENTS\.md|\.mcp\.json|keybindings\.json|\.claude[\/\\](hooks|agents|commands|skills|plugins|memory)))(?=.*(writeFile|appendFile|createWriteStream|open\([^)]*['"][wa]\+?['"]|\.write_text|\.write\(|(^|[^=<>\-\w])>>?\s*["']?[~$%\w.\/\\:{}-]*(settings|CLAUDE|MEMORY|AGENTS|\.mcp|\.claude|keybindings)|Set-Content|Add-Content|Out-File|\bcp\s|\bcopy\b|\bmv\s|\btee\b|\b(add|append|write|insert|edit|modify|update|inject)\b.{0,40}\b(to|into|in)\b))/i,
    why: 'Writes to Claude config/memory files: can plant persistent instructions, hooks or permissions that outlive the skill.' },
  { id: 'persist-os', sev: 'high', cat: 'persistence', files: 'all',
    re: /(\.bashrc|\.zshrc|\.bash_profile|\.profile\b|crontab|schtasks|Start-?up[\/\\]|CurrentVersion\\Run|New-ScheduledTask|Register-ScheduledTask|launchctl|LaunchAgents|systemctl\s+(enable|--user)|\$PROFILE|Microsoft\.PowerShell_profile|git\s+config\s+--global\s+(core\.hooksPath|alias))/i,
    why: 'Sets up something that runs again later (startup, cron, shell profile).' },
  { id: 'security-tamper', sev: 'critical', cat: 'persistence', files: 'all',
    re: /(Set-MpPreference|Add-MpPreference\s+-Exclusion|DisableRealtimeMonitoring|Set-ExecutionPolicy\s+(Bypass|Unrestricted)|-ExecutionPolicy\s+Bypass|netsh\s+advfirewall|ufw\s+disable|setenforce\s+0|spctl\s+--master-disable|xattr\s+-d\s+com\.apple\.quarantine)/i,
    why: 'Disables antivirus, firewall or OS security controls.' },

  // Destruction
  { id: 'destructive', sev: 'high', cat: 'destructive', files: 'all',
    re: /(rm\s+-[a-z]*r[a-z]*f?\s+(\/|~|\$HOME|\*)(\s|$)|rm\s+-[a-z]*f[a-z]*r\s+(\/|~|\$HOME)|Remove-Item\b[^\n]*-Recurse[^\n]*(\$HOME|\$env:USERPROFILE|C:\\)|shutil\.rmtree\(\s*(os\.path\.expanduser|Path\.home|['"]\/)|rd\s+\/s\s+\/q\s+[A-Z]:\\|format\s+[A-Z]:|mkfs\.|dd\s+if=.*of=\/dev\/|git\s+push\s+(-f|--force)|cipher\s+\/w|vssadmin\s+delete)/i,
    why: 'Can wipe files, disks or git history.' },

  // Obfuscation
  { id: 'obfuscation-decode', sev: 'medium', cat: 'obfuscation', files: 'all',
    re: /(base64\s+(-d|--decode)|b64decode|atob\s*\(|Buffer\.from\([^)]*['"]base64['"]\)|FromBase64String|-enc(odedcommand)?\s+[A-Za-z0-9+\/=]{20,}|String\.fromCharCode\(|marshal\.loads|zlib\.decompress|codecs\.decode\([^)]*rot)/i,
    why: 'Decodes hidden data at runtime; decode it yourself and read what it is.' },
];

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.py', '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.bat', '.cmd', '.rb', '.pl', '.go', '.rs', '.php', '.lua', '.vbs']);
const MD_EXT = new Set(['.md', '.mdx', '.markdown', '.txt']);
const BINARY_RISK_EXT = new Set(['.exe', '.dll', '.so', '.dylib', '.bin', '.scr', '.msi', '.com', '.jar', '.class', '.pyc', '.node', '.wasm', '.app', '.dmg', '.pkg', '.deb', '.rpm']);
const ARCHIVE_EXT = new Set(['.zip', '.tar', '.gz', '.tgz', '.7z', '.rar', '.xz', '.bz2']);
const SKIP_DIRS = new Set(['.git', 'node_modules', '__pycache__', '.venv', 'venv']);

// Invisible / direction-changing characters Claude reads but humans don't see.
const HIDDEN_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u00AD\u180E\uFEFF]|[\u{E0000}-\u{E007F}]/gu;
const TAG_RE = /[\u{E0000}-\u{E007F}]+/gu;

// ---------------------------------------------------------------- helpers
function sha(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

function walk(dir, out = [], root = dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) { out.push({ path: p, symlink: true }); continue; }
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(p, out, root); continue; }
    if (e.isFile()) out.push({ path: p });
  }
  return out;
}

function escapeInvisible(s) {
  return s.replace(HIDDEN_RE, ch => `<U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}>`);
}

function snippet(line) {
  const t = escapeInvisible(line.trim());
  return t.length > 160 ? t.slice(0, 157) + '...' : t;
}

function frontmatter(text) {
  const m = text.match(/^\uFEFF?---\r?\n([\s\S]*?)\r?\n---/);
  return m ? m[1] : null;
}

// ---------------------------------------------------------------- discovery
function isSkillDir(d) { return fs.existsSync(path.join(d, 'SKILL.md')); }
function isPluginDir(d) { return fs.existsSync(path.join(d, '.claude-plugin', 'plugin.json')) || fs.existsSync(path.join(d, 'hooks', 'hooks.json')); }

function expandTarget(p) {
  const abs = path.resolve(p.replace(/^~(?=$|[\/\\])/, HOME));
  if (!fs.existsSync(abs)) return [];
  if (fs.statSync(abs).isFile()) return [{ kind: 'file', dir: abs, name: path.basename(abs) }];
  if (isPluginDir(abs)) return [{ kind: 'plugin', dir: abs, name: path.basename(abs) }];
  if (isSkillDir(abs)) return [{ kind: 'skill', dir: abs, name: path.basename(abs) }];
  // A folder of skills/plugins
  const units = [];
  for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    const d = path.join(abs, e.name);
    if (isPluginDir(d)) units.push({ kind: 'plugin', dir: d, name: e.name });
    else if (isSkillDir(d)) units.push({ kind: 'skill', dir: d, name: e.name });
  }
  if (!units.length) units.push({ kind: 'folder', dir: abs, name: path.basename(abs) });
  return units;
}

function defaultTargets() {
  const units = [];
  const dirs = [path.join(CLAUDE, 'skills'), path.join(process.cwd(), '.claude', 'skills')];
  for (const d of dirs) if (fs.existsSync(d)) units.push(...expandTarget(d));
  // Installed plugins (only the active install path, not every cached version)
  try {
    const reg = JSON.parse(fs.readFileSync(path.join(CLAUDE, 'plugins', 'installed_plugins.json'), 'utf8'));
    for (const [id, installs] of Object.entries(reg.plugins || {})) {
      for (const inst of [].concat(installs)) {
        if (inst.installPath && fs.existsSync(inst.installPath)) units.push({ kind: 'plugin', dir: inst.installPath, name: id });
      }
    }
  } catch { /* no plugins */ }
  // Dedupe and never audit ourselves
  const seen = new Set();
  return units.filter(u => {
    const k = path.resolve(u.dir).toLowerCase();
    if (seen.has(k) || k === path.resolve(SELF_DIR).toLowerCase()) return false;
    seen.add(k); return true;
  });
}

// ---------------------------------------------------------------- scanning
function scanUnit(unit) {
  const files = unit.kind === 'file' ? [{ path: unit.dir }] : walk(unit.dir);
  const findings = [];
  const urls = new Set();
  const hash = crypto.createHash('sha256');
  const add = (f) => findings.push(f);
  const rel = (p) => unit.kind === 'file' ? path.basename(p) : path.relative(unit.dir, p) || path.basename(p);

  for (const f of files.sort((a, b) => a.path.localeCompare(b.path))) {
    const r = rel(f.path);
    if (f.symlink) {
      let target = '?';
      try { target = fs.realpathSync(f.path); } catch {}
      const inside = target.toLowerCase().startsWith(path.resolve(unit.dir).toLowerCase());
      add({ id: 'symlink', sev: inside ? 'low' : 'high', cat: 'filesystem', file: r, line: 0,
        text: `-> ${target}`, why: inside ? 'Symlink inside the skill.' : 'Symlink pointing outside the skill (can expose or overwrite other files).' });
      continue;
    }
    const ext = path.extname(f.path).toLowerCase();
    let buf;
    try { buf = fs.readFileSync(f.path); } catch { continue; }
    hash.update(r).update(buf);

    if (BINARY_RISK_EXT.has(ext)) { add({ id: 'binary-executable', sev: 'high', cat: 'opaque-code', file: r, line: 0, text: `${buf.length} bytes`, why: 'Compiled/binary executable: cannot be reviewed by reading.' }); continue; }
    if (ARCHIVE_EXT.has(ext)) { add({ id: 'archive', sev: 'medium', cat: 'opaque-code', file: r, line: 0, text: `${buf.length} bytes`, why: 'Archive bundled inside a skill; contents are not visible. Extract into an empty folder and scan it.' }); continue; }
    if (buf.length > MAX_TEXT_BYTES) { add({ id: 'large-file', sev: 'low', cat: 'opaque-code', file: r, line: 0, text: `${buf.length} bytes`, why: 'Very large file; skipped by the scanner, review manually.' }); continue; }
    if (buf.includes(0)) {
      if (!/\.(png|jpe?g|gif|webp|ico|svg|pdf|woff2?|ttf|otf)$/i.test(ext)) add({ id: 'binary-unknown', sev: 'medium', cat: 'opaque-code', file: r, line: 0, text: `${buf.length} bytes`, why: 'Binary content with an unexpected extension.' });
      continue;
    }

    const text = buf.toString('utf8');
    const isMd = MD_EXT.has(ext);
    const isCode = CODE_EXT.has(ext) || /^#!/.test(text);
    const isConfig = /\.(json|ya?ml|toml)$/i.test(ext);

    // Hidden characters (skip a single leading BOM)
    const body = text.replace(/^\uFEFF/, '');
    const hiddenLines = new Map();
    body.split(/\r?\n/).forEach((ln, i) => { const m = ln.match(HIDDEN_RE); if (m) hiddenLines.set(i + 1, m.length); });
    if (hiddenLines.size) {
      const tags = [...body.matchAll(TAG_RE)].map(m => [...m[0]].map(c => String.fromCharCode(c.codePointAt(0) - 0xE0000)).join(''));
      const [firstLine] = hiddenLines.keys();
      const count = [...hiddenLines.values()].reduce((a, b) => a + b, 0);
      const onlySoftHyphen = !tags.length && !/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u180E\uFEFF]/u.test(body);
      add({ id: tags.length ? 'hidden-tag-text' : 'hidden-unicode', sev: tags.length ? 'critical' : onlySoftHyphen ? 'low' : 'high', cat: 'hidden-content',
        file: r, line: firstLine, text: tags.length ? `decoded hidden text: "${tags.join(' | ').slice(0, 300)}"` : `${count} invisible char(s) on ${hiddenLines.size} line(s)`,
        why: tags.length ? 'Unicode tag characters hide instructions only the AI can read.' : 'Invisible/bidi characters can hide or reorder text you review.' });
    }

    // HTML comments in markdown: invisible when rendered, fully visible to Claude
    if (isMd) {
      for (const m of body.matchAll(/<!--([\s\S]*?)-->/g)) {
        const c = m[1].trim();
        if (c.length < 15) continue;
        const line = body.slice(0, m.index).split('\n').length;
        add({ id: 'hidden-html-comment', sev: /\b(ignore|instruction|must|always|never|do not|curl|http|send|upload|secret|key|token)\b/i.test(c) ? 'high' : 'low',
          cat: 'hidden-content', file: r, line, text: snippet(c), why: 'HTML comment: hidden in rendered view but read by Claude.' });
      }
    }

    // Frontmatter checks (SKILL.md / commands / agents)
    if (isMd) {
      const fm = frontmatter(body);
      if (fm) {
        const desc = (fm.match(/description:\s*(>-?|\|-?)?\s*([\s\S]*?)(?=\n[\w-]+:|$)/) || [])[2] || '';
        const rule = RULES.find(x => x.id === 'trigger-hijack');
        if (rule.re.test(desc)) add({ id: rule.id, sev: rule.sev, cat: rule.cat, file: r, line: 1, text: snippet(desc), why: rule.why });
        const tools = (fm.match(/allowed-tools:\s*(.*)/) || [])[1];
        if (tools && (/(^|[\s,])\*($|[\s,])/.test(tools) || /\bBash\b(?!\()|Bash\(\s*\*\s*\)/.test(tools)))
          add({ id: 'broad-allowed-tools', sev: 'high', cat: 'permission-bypass', file: r, line: 1, text: snippet(tools), why: 'Pre-approves ANY shell command while the skill runs, with no prompt.' });
        else if (tools && /Bash\(\s*(node|python3?|bash|sh|pwsh|powershell|npx|deno|bun|ruby|perl)\s*:\s*\*\s*\)/i.test(tools))
          add({ id: 'interpreter-allowed-tools', sev: 'low', cat: 'permission-bypass', file: r, line: 1, text: snippet(tools), why: 'Pre-approves an interpreter with any arguments; effectively any code via that interpreter.' });
      }
    }

    // Plugin hooks: list every command that runs automatically
    if (/hooks\.json$/i.test(r) || (/plugin\.json$/i.test(r) && /"hooks"/.test(body))) {
      for (const m of body.matchAll(/"command"\s*:\s*"((?:[^"\\]|\\.)*)"/g)) {
        add({ id: 'auto-hook', sev: 'medium', cat: 'auto-execution', file: r, line: body.slice(0, m.index).split('\n').length,
          text: snippet(m[1]), why: 'Runs automatically on Claude events without you invoking the skill. Read the script it calls.' });
      }
    }
    if (/\.mcp\.json$/i.test(r) || (/plugin\.json$/i.test(r) && /"mcpServers"/.test(body))) {
      add({ id: 'mcp-server', sev: 'medium', cat: 'auto-execution', file: r, line: 1, text: 'declares MCP server(s)', why: 'Starts a background server process with its own tools. Check what it runs.' });
    }

    // Line rules
    const lines = body.split(/\r?\n/);
    const hitPerRule = new Map();
    lines.forEach((ln, i) => {
      for (const u of ln.matchAll(/https?:\/\/[^\s"'`)<>\]]+/g)) urls.add(u[0].replace(/[.,;]+$/, ''));
      for (const rule of RULES) {
        if (rule.files === 'frontmatter') continue;
        if (rule.files === 'md' && !isMd) continue;
        if (rule.files === 'code' && !(isCode || isConfig)) continue;
        if (!rule.re.test(ln)) continue;
        const n = (hitPerRule.get(rule.id) || 0) + 1;
        hitPerRule.set(rule.id, n);
        if (n > 5) continue; // cap noise per file
        add({ id: rule.id, sev: rule.sev, cat: rule.cat, file: r, line: i + 1, text: snippet(ln), why: rule.why });
      }
      // Long base64-looking blobs
      const blob = ln.match(/[A-Za-z0-9+\/]{200,}={0,2}/);
      if (blob && !/^data:image\//.test(ln.trim())) {
        let preview = '';
        try { preview = Buffer.from(blob[0], 'base64').toString('utf8').replace(/[^\x20-\x7E]/g, '.').slice(0, 80); } catch {}
        add({ id: 'encoded-blob', sev: 'medium', cat: 'obfuscation', file: r, line: i + 1, text: `${blob[0].length} chars, decodes to: "${preview}"`, why: 'Large encoded blob may hide a payload or instructions.' });
      }
    });
    for (const [id, n] of hitPerRule) if (n > 5) add({ id, sev: 'info', cat: 'note', file: r, line: 0, text: `${n - 5} more match(es) not shown`, why: '' });
  }

  const max = findings.reduce((m, f) => Math.max(m, SEV_RANK[f.sev]), 0);
  const verdict = max >= 4 ? 'DANGEROUS' : max === 3 ? 'SUSPICIOUS' : max === 2 ? 'REVIEW' : 'CLEAN';
  findings.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || a.file.localeCompare(b.file) || a.line - b.line);
  return { name: unit.name, kind: unit.kind, dir: unit.dir, files: files.length, hash: hash.digest('hex'), verdict, findings, urls: [...urls].sort() };
}

// ---------------------------------------------------------------- state (--changed / --accept)
function loadState() { try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return { accepted: {} }; } }
function saveState(s) { fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true }); fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2)); }
const key = (u) => path.resolve(u.dir).toLowerCase();

// ---------------------------------------------------------------- human-readable report
// Colour only in a real terminal (and never with NO_COLOR); Unicode box/icons unless --ascii or
// SKILL_GUARD_ASCII=1. The --json output used by the hooks is unaffected by any of this.
const ASCII = process.argv.includes('--ascii') || process.env.SKILL_GUARD_ASCII === '1';
const COLOR = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const WIDTH = Math.min(Math.max(process.stdout.columns || 100, 72), 110);
const glyph = (unicode, ascii) => (ASCII ? ascii : unicode);
const SEP = glyph('·', '|');
const paint = (open) => (s) => (COLOR ? `\x1b[${open}m${s}\x1b[0m` : String(s));
const style = {
  bold: paint('1'), dim: paint('2'), red: paint('31'), green: paint('32'), yellow: paint('33'), cyan: paint('36'),
  boldRed: paint('1;31'), boldYellow: paint('1;33'), boldCyan: paint('1;36'), boldGreen: paint('1;32'),
};
const VERDICT_STYLE = {
  DANGEROUS: { icon: glyph('✖', '[X]'), color: style.boldRed, says: 'Do not install. It contains patterns that can harm you; read the findings.' },
  SUSPICIOUS: { icon: glyph('⚠', '[!]'), color: style.boldYellow, says: 'Looks risky. Check every finding before you install or keep it.' },
  REVIEW: { icon: glyph('◆', '[?]'), color: style.boldCyan, says: 'Nothing known-bad, but parts run on their own or need a human look.' },
  CLEAN: { icon: glyph('✔', '[ok]'), color: style.boldGreen, says: 'No known risk patterns found.' },
};
const SEV_STYLE = { critical: style.boldRed, high: style.red, medium: style.yellow, low: style.dim, info: style.dim };

const fit = (s, n) => (s.length > n ? `${s.slice(0, Math.max(0, n - 1))}${glyph('…', '~')}` : s);
const rule = (label = '') => {
  const bar = glyph('━', '=');
  const head = label ? `${bar}${bar} ${label} ` : '';
  const visible = head.replace(/\x1b\[[0-9;]*m/g, '');
  return head + bar.repeat(Math.max(4, WIDTH - visible.length));
};

/** URLs grouped by host, most frequent first: "github.com ×14 · sec.gov ×3". */
function hostSummary(urls) {
  const hosts = new Map();
  for (const u of urls) {
    let h;
    try { h = new URL(u).host || u; } catch { h = u.replace(/^\w+:\/\//, '').split(/[/?#]/)[0]; }
    h = h.replace(/[}\])>'",.;]+$/, ''); // template/markdown punctuation stuck to the URL in the source
    hosts.set(h, (hosts.get(h) || 0) + 1);
  }
  return [...hosts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([h, n]) => (n > 1 ? `${h} ${glyph('×', 'x')}${n}` : h));
}

/** A plugin scanned by path is named after its version folder ("0.1.2"); show "my-plugin 0.1.2" instead. */
function displayName(r) {
  if (!/^v?\d+(\.\d+)+/.test(r.name)) return r.name;
  return `${path.basename(path.dirname(r.dir))} ${r.name}`;
}

function printUnit(r, { brief }) {
  const v = VERDICT_STYLE[r.verdict];
  const status = r.status ? ` ${SEP} ${r.status}` : '';
  console.log('');
  console.log(v.color(rule(`${v.icon} ${r.verdict}`)));
  console.log(`  ${style.bold(`${r.kind} "${displayName(r)}"`)}${style.dim(` ${SEP} ${r.files} files${status}`)}`);
  console.log(`  ${v.says}`);
  console.log(style.dim(`  ${r.dir}`));

  const shown = r.findings.filter((f) => f.sev !== 'info' || !brief);
  if (shown.length) {
    const count = (s) => r.findings.filter((f) => f.sev === s).length;
    const dot = glyph('●', '*');
    const tally = ['critical', 'high', 'medium', 'low']
      .map((s) => (count(s) ? SEV_STYLE[s](`${dot} ${count(s)} ${s}`) : style.dim(`${dot} 0 ${s}`)))
      .join('   ');
    console.log(`\n  ${style.bold('Findings')}   ${tally}`);

    // One block per rule: the explanation once, then every place it matched.
    const groups = new Map();
    for (const f of shown) {
      const k = `${f.sev}|${f.id}`;
      if (!groups.has(k)) groups.set(k, { sev: f.sev, id: f.id, why: f.why, hits: [] });
      groups.get(k).hits.push(f);
    }
    for (const g of groups.values()) {
      const times = g.hits.length > 1 ? style.dim(` ${glyph('×', 'x')}${g.hits.length}`) : '';
      console.log(`\n  ${SEV_STYLE[g.sev](g.sev.toUpperCase().padEnd(8))} ${style.bold(g.id)}${times}`);
      if (g.why) console.log(`  ${' '.repeat(9)}${g.why}`);
      const where = g.hits.map((f) => `${f.file}${f.line ? `:${f.line}` : ''}`);
      const pad = Math.min(Math.max(...where.map((w) => w.length)), 40);
      g.hits.forEach((f, i) => {
        const loc = where[i].padEnd(pad);
        const text = f.text ? fit(f.text.replace(/\\"/g, '"').replace(/\s+/g, ' '), WIDTH - pad - 16) : '';
        console.log(`  ${' '.repeat(9)}${style.cyan(glyph('▸', '>'))} ${loc}  ${style.dim(text)}`);
      });
    }
  }
  if (r.urls.length) {
    const hosts = hostSummary(r.urls);
    const line = fit(hosts.join(` ${SEP} `), WIDTH - 16);
    console.log(`\n  ${style.bold('Network')}    ${line}  ${style.dim(`(${r.urls.length} URLs)`)}`);
  } else {
    console.log(`\n  ${style.bold('Network')}    ${style.dim('no URLs in the files')}`);
  }
}

/**
 * Compact report for a model or a pipe (stdout is not a terminal): the same facts in a fraction of the tokens.
 * One line per rule with all its locations, a snippet only for medium and worse, hosts summarised, clean units
 * on one line. Box drawing and blank lines cost tokens and tell a model nothing.
 */
function printCompact(results, { brief }) {
  if (!results.length) return console.log('No new or changed skills since the last review.');
  const quiet = results.filter((r) => r.verdict === 'CLEAN' && !r.findings.some((f) => f.sev !== 'info'));
  const order = { DANGEROUS: 0, SUSPICIOUS: 1, REVIEW: 2, CLEAN: 3 };
  for (const r of results.filter((x) => !quiet.includes(x)).sort((a, b) => order[a.verdict] - order[b.verdict])) {
    console.log(`${r.verdict} ${r.kind} ${displayName(r)} (${r.files} files${r.status ? `, ${r.status}` : ''}) ${r.dir}`);
    const groups = new Map();
    for (const f of r.findings.filter((x) => x.sev !== 'info' || !brief)) {
      const k = `${f.sev}|${f.id}`;
      if (!groups.has(k)) groups.set(k, { sev: f.sev, id: f.id, why: f.why, hits: [] });
      groups.get(k).hits.push(f);
    }
    for (const g of groups.values()) {
      // "hooks/hooks.json:7,13,19; lib/run.mjs:35": each path once, its line numbers after it.
      const byFile = new Map();
      for (const f of g.hits) {
        const file = f.file.replace(/\\/g, '/');
        if (!byFile.has(file)) byFile.set(file, []);
        if (f.line) byFile.get(file).push(f.line);
      }
      const where = [...byFile].map(([file, lines]) => (lines.length ? `${file}:${lines.join(',')}` : file)).join('; ');
      const first = g.hits[0];
      const snippet =
        SEV_RANK[g.sev] >= 2 && first.text ? ` \`${fit(first.text.replace(/\\"/g, '"').replace(/\s+/g, ' '), 90)}\`` : '';
      console.log(` ${g.sev} ${g.id}${g.hits.length > 1 ? ` x${g.hits.length}` : ''}: ${where}${snippet}${g.why ? ` - ${g.why}` : ''}`);
    }
    if (r.urls.length) console.log(` net (${r.urls.length} URLs): ${fit(hostSummary(r.urls).join(', ').replace(/ ×/g, ' x'), 160)}`);
  }
  if (quiet.length) console.log(`CLEAN (${quiet.length}): ${quiet.map((r) => r.name).join(', ')}`);
  const counts = results.reduce((c, r) => ((c[r.verdict] = (c[r.verdict] || 0) + 1), c), {});
  console.log(`Summary: ${['DANGEROUS', 'SUSPICIOUS', 'REVIEW', 'CLEAN'].map((k) => `${counts[k] || 0} ${k}`).join(', ')}. Static triage only.`);
}

function printReport(results, opts) {
  if (!results.length) {
    console.log(`${style.green(glyph('✔', '[ok]'))} No new or changed skills since the last review.`);
    return;
  }
  // Units with nothing to say get one line each at the top; the rest get a full block.
  const quiet = results.filter((r) => r.verdict === 'CLEAN' && !r.findings.some((f) => f.sev !== 'info'));
  const loud = results.filter((r) => !quiet.includes(r));
  if (quiet.length) {
    console.log('');
    console.log(style.boldGreen(rule(`${VERDICT_STYLE.CLEAN.icon} CLEAN (${quiet.length})`)));
    const width = Math.max(...quiet.map((r) => r.name.length));
    for (const r of quiet) {
      const hosts = hostSummary(r.urls);
      const net = hosts.length ? `network: ${fit(hosts.join(', '), WIDTH - width - 32)}` : 'no network';
      console.log(`  ${style.green(VERDICT_STYLE.CLEAN.icon)} ${r.name.padEnd(width)}  ${style.dim(`${String(r.files).padStart(3)} files ${SEP} ${net}`)}`);
    }
  }
  const order = { DANGEROUS: 0, SUSPICIOUS: 1, REVIEW: 2, CLEAN: 3 };
  for (const r of loud.sort((a, b) => order[a.verdict] - order[b.verdict] || a.name.localeCompare(b.name))) printUnit(r, opts);

  const counts = results.reduce((c, r) => ((c[r.verdict] = (c[r.verdict] || 0) + 1), c), {});
  console.log('');
  console.log(style.bold(rule('Summary')));
  console.log(
    '  ' +
      ['DANGEROUS', 'SUSPICIOUS', 'REVIEW', 'CLEAN']
        .map((k) => (counts[k] ? VERDICT_STYLE[k].color(`${VERDICT_STYLE[k].icon} ${counts[k]} ${k}`) : style.dim(`${VERDICT_STYLE[k].icon} 0 ${k}`)))
        .join('     '),
  );
  console.log(style.dim('  Static triage only: patterns, not proof. Read the code before trusting a CLEAN result.'));
}

// ---------------------------------------------------------------- main
const args = process.argv.slice(2);
const flags = new Set(args.filter(a => a.startsWith('--')));
const positional = args.filter(a => !a.startsWith('--'));

if (flags.has('--help')) { console.log(fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 12).join('\n')); process.exit(0); }

let units = positional.length ? positional.flatMap(expandTarget) : defaultTargets();

if (flags.has('--accept')) {
  if (!positional.length) {
    // Accept by name among installed units
    console.error('usage: --accept <path|name>'); process.exit(3);
  }
  if (!units.length) units = defaultTargets().filter(u => positional.some(p => u.name === p || u.name.startsWith(p + '@')));
  if (!units.length) { console.error('nothing matched'); process.exit(3); }
  const st = loadState();
  for (const u of units) {
    const r = scanUnit(u);
    st.accepted[key(u)] = { name: u.name, hash: r.hash, verdict: r.verdict, at: new Date().toISOString() };
    console.log(`${style.green(glyph('✔', '[ok]'))} Recorded ${style.bold(`"${u.name}"`)} as reviewed  ${style.dim(`(${r.verdict}, fingerprint ${r.hash.slice(0, 12)})`)}`);
    console.log(style.dim(`  It is flagged again only if its files change.`));
  }
  saveState(st); process.exit(0);
}

if (!units.length) { console.error('No skills or plugins found at the given path(s).'); process.exit(3); }

let results = units.map(scanUnit);
if (flags.has('--changed')) {
  const st = loadState();
  results = results.filter(r => st.accepted[path.resolve(r.dir).toLowerCase()]?.hash !== r.hash)
    .map(r => ({ ...r, status: st.accepted[path.resolve(r.dir).toLowerCase()] ? 'changed' : 'new' }));
}

if (flags.has('--json')) {
  console.log(JSON.stringify(results, null, 2));
} else if (flags.has('--quiet') && !results.length) {
  // nothing new: print nothing (used by hooks)
} else if (process.stdout.isTTY || flags.has('--pretty')) {
  printReport(results, { brief: flags.has('--brief') });
} else {
  printCompact(results, { brief: flags.has('--brief') });
}

const worst = results.reduce((m, r) => Math.max(m, { CLEAN: 0, REVIEW: 0, SUSPICIOUS: 1, DANGEROUS: 2 }[r.verdict]), 0);
process.exit(worst);
