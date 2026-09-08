export type Severity = "critical" | "high" | "medium" | "low";

export type Layer = "static" | "behavioral" | "provenance" | "network";

export interface Rule {
  id: string;
  layer: Layer;
  severity: Severity;
  title: string;
  rationale: string;
  remediation: string;
  /** Matched against each line of every text file in the artifact. */
  pattern: RegExp;
  /** Restrict the rule to files whose path matches. */
  pathPattern?: RegExp;
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 18,
  medium: 7,
  low: 2,
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

/**
 * Detection rules. Every rule is a real, evaluated check — there is no
 * placeholder content here. Rule IDs are stable and safe to reference in
 * policy or ticketing systems.
 */
export const RULES: Rule[] = [
  // ── Layer 1: static instruction analysis ────────────────────────────────
  {
    id: "PGR-S001",
    layer: "static",
    severity: "critical",
    title: "Instruction override of system or operator policy",
    rationale:
      "The skill instructs the model to disregard system prompts, operator rules, or prior guidance. This is the core primitive of a prompt-injection payload.",
    remediation:
      "Remove the override language. A legitimate skill never needs to countermand the host system prompt.",
    pattern:
      /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(all\s+)?(previous|prior|earlier|above|system|operator|prior)\b[^.\n]{0,25}\b(instruction|prompt|rule|policy|guideline|message)/i,
  },
  {
    id: "PGR-S002",
    layer: "static",
    severity: "critical",
    title: "Instruction to conceal actions from the user",
    rationale:
      "The skill asks the assistant to hide, omit, or misreport what it is doing. Concealment has no legitimate use and defeats human oversight.",
    remediation: "Delete the concealment instruction and disclose all actions the skill performs.",
    pattern:
      /\b(do\s*not|don'?t|never)\b[^.\n]{0,30}\b(tell|inform|mention|reveal|show|disclose|notify|alert|log)\b[^.\n]{0,25}\b(the\s+)?(user|human|operator|owner)\b|\b(without|avoid)\b[^.\n]{0,20}\b(telling|informing|notifying|user'?s?\s+knowledge|user\s+consent)\b|\bsilently\b[^.\n]{0,25}\b(send|upload|copy|post|exfil|transmit|delete|run|execute)\b/i,
  },
  {
    id: "PGR-S003",
    layer: "static",
    severity: "high",
    title: "Safety or refusal-behaviour suppression",
    rationale:
      "The skill attempts to disable refusals, safety checks, or content policy enforcement for its own execution.",
    remediation: "Remove language that suppresses safety behaviour.",
    pattern:
      /\b(no\s+matter\s+what|regardless\s+of)\b[^.\n]{0,30}\b(polic|safety|rule|guideline)|\b(disable|turn\s+off|suspend|skip)\b[^.\n]{0,25}\b(safety|guardrail|filter|moderation|refusal|restriction)|\byou\s+are\s+now\s+(in\s+)?(developer|dan|god|unrestricted|jailbreak)\s*mode/i,
  },
  {
    id: "PGR-S004",
    layer: "static",
    severity: "high",
    title: "Approval-bypass instruction",
    rationale:
      "The skill instructs the agent to proceed without confirmation on actions that normally require a human in the loop.",
    remediation: "Restore explicit confirmation before destructive or outbound actions.",
    pattern:
      /\b(without|skip|bypass|no\s+need\s+for|do\s*not\s+ask\s+for)\b[^.\n]{0,25}\b(confirmation|approval|permission|consent|asking)\b|\bauto[-\s]?approve\b/i,
  },
  {
    id: "PGR-S005",
    layer: "static",
    severity: "critical",
    title: "Hidden instruction in HTML comment",
    rationale:
      "Instructions inside HTML comments are invisible in rendered markdown but still reach the model. This is a classic smuggling technique.",
    remediation: "Move all instructions into visible markdown, or remove them.",
    pattern:
      /<!--[^>]{0,400}\b(you\s+must|always|ignore|system|instruction|secret|do\s*not\s+tell|send|upload|token|key)\b/i,
  },
  {
    id: "PGR-S006",
    layer: "static",
    severity: "critical",
    title: "Zero-width or bidirectional control characters",
    rationale:
      "Invisible Unicode (zero-width joiners, bidi overrides, Unicode tag block) can hide an entirely separate instruction stream from human reviewers.",
    remediation: "Strip all non-printing control characters from the skill files.",
    pattern: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\uE0000-\uE007F]/,
  },
  {
    id: "PGR-S007",
    layer: "static",
    severity: "high",
    title: "Large opaque base64 blob",
    rationale:
      "A long encoded string inside an instruction file typically carries a payload that is unreadable at review time.",
    remediation: "Replace the encoded blob with its plaintext equivalent, or remove it.",
    pattern: /(?:^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?:$|[^A-Za-z0-9+/=])/,
  },
  {
    id: "PGR-S008",
    layer: "static",
    severity: "high",
    title: "Runtime decoding of an embedded payload",
    rationale:
      "Decoding base64/hex at runtime and feeding the result to an interpreter hides the executed code from static review.",
    remediation: "Inline the real command so reviewers can read it.",
    pattern:
      /\b(base64\s+(-{1,2}d(ecode)?)|atob\s*\(|from_?base64|b64decode|fromhex|Convert\.FromBase64String)\b/i,
  },
  {
    id: "PGR-S009",
    layer: "static",
    severity: "medium",
    title: "Role-play or persona reframing of the assistant",
    rationale:
      "Reframing the assistant's identity is frequently used to detach it from operator policy.",
    remediation: "Describe the task, not a new identity for the model.",
    pattern:
      /\b(you\s+are\s+no\s+longer|pretend\s+(to\s+be|you)|act\s+as\s+if\s+you\s+(have|are)\s+no|from\s+now\s+on\s+you\s+(are|will))\b/i,
  },
  {
    id: "PGR-S010",
    layer: "static",
    severity: "medium",
    title: "Urgency or authority pressure language",
    rationale:
      "Manufactured urgency and false authority claims are social-engineering markers used to push an agent past its checks.",
    remediation: "Remove pressure language; state the task plainly.",
    pattern:
      /\b(this\s+is\s+(an\s+)?(urgent|emergency|critical)\b[^.\n]{0,30}\b(must|immediately))|\b(authorized|approved|mandated)\s+by\s+(the\s+)?(admin|administrator|security\s+team|management|anthropic|openai)\b/i,
  },
  {
    id: "PGR-S011",
    layer: "static",
    severity: "low",
    title: "Missing or malformed skill frontmatter",
    rationale:
      "A skill without a declared name and description cannot be governed, inventoried, or attributed.",
    remediation: "Add YAML frontmatter with at least `name` and `description`.",
    pattern: /^\uFFFF$/, // evaluated structurally in the engine, never line-matched
    pathPattern: /^\uFFFF$/,
  },

  // ── Layer 2: behavioral / capability analysis ───────────────────────────
  {
    id: "PGR-B001",
    layer: "behavioral",
    severity: "critical",
    title: "Credential and secret file access",
    rationale:
      "The skill reads well-known secret locations. Combined with any outbound call this is a direct credential-theft chain.",
    remediation: "Remove secret-store access, or scope the skill to explicit, non-secret inputs.",
    pattern:
      /(\.env(\.[a-z]+)?\b|~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.kube\/config|\.npmrc|\.netrc|\.git-credentials|keychain|credentials\.json|service[-_]account\.json)/i,
  },
  {
    id: "PGR-B002",
    layer: "behavioral",
    severity: "critical",
    title: "Remote code fetched and piped to a shell",
    rationale:
      "`curl … | sh` style chains execute attacker-controlled code that never appears in the reviewed artifact.",
    remediation: "Vendor the script into the skill and review it, or remove the chain.",
    pattern:
      /\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]{0,160}\|\s*(sudo\s+)?(ba|z|k|d)?sh\b|\b(curl|wget)\b[^\n]{0,120}&&\s*(chmod\s+\+x|\.\/)/i,
  },
  {
    id: "PGR-B003",
    layer: "behavioral",
    severity: "critical",
    title: "Destructive filesystem or repository operation",
    rationale: "Irreversible deletion or history rewriting can destroy production data or evidence.",
    remediation: "Remove the destructive command or gate it behind explicit human approval.",
    pattern:
      /\brm\s+-[a-z]*[rf][a-z]*\s+(\/|~|\$HOME|\*)|\bgit\s+push\s+(--force|-f)\b|\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\s+TABLE\b|\bmkfs\b|\bdd\s+if=.*of=\/dev\//i,
  },
  {
    id: "PGR-B004",
    layer: "behavioral",
    severity: "high",
    title: "Dynamic code execution",
    rationale:
      "eval/exec on assembled strings makes the skill's real behaviour undecidable from the source.",
    remediation: "Replace dynamic execution with explicit, reviewable code paths.",
    pattern:
      /\b(eval\s*\(|exec\s*\(|new\s+Function\s*\(|subprocess\.(Popen|call|run)\s*\([^)]*shell\s*=\s*True|child_process|os\.system\s*\(|Invoke-Expression|IEX\s*\()/i,
  },
  {
    id: "PGR-B005",
    layer: "behavioral",
    severity: "high",
    title: "Persistence mechanism",
    rationale:
      "Writing to shell profiles, cron, systemd, or git hooks lets the payload survive after the skill run ends.",
    remediation: "Remove persistence; a skill should be stateless within its invocation.",
    pattern:
      /\b(crontab\s+-|\/etc\/cron|systemctl\s+(enable|--user)|launchctl\s+load|\.bashrc|\.zshrc|\.bash_profile|\.profile\b|\.git\/hooks|LaunchAgents|registry\s+add|HKCU\\)/i,
  },
  {
    id: "PGR-B006",
    layer: "behavioral",
    severity: "high",
    title: "Privilege escalation",
    rationale: "The skill attempts to run with elevated rights beyond its declared scope.",
    remediation: "Run at least privilege; drop sudo/admin escalation.",
    pattern: /\b(sudo\s+(-S|su\b|-i\b)|chmod\s+777|setuid|runas\s+\/user:administrator|pkexec)\b/i,
  },
  {
    id: "PGR-B007",
    layer: "behavioral",
    severity: "high",
    title: "Broad environment variable harvesting",
    rationale:
      "Dumping the whole environment collects every injected secret in one call, regardless of what the skill needs.",
    remediation: "Read only the specific variables the skill requires.",
    pattern:
      /\b(printenv\b|env\s*\|\s*(curl|nc|base64|grep)|os\.environ\b(?!\s*\[)|process\.env\s*\)|JSON\.stringify\s*\(\s*process\.env)/i,
  },
  {
    id: "PGR-B008",
    layer: "behavioral",
    severity: "medium",
    title: "Undeclared tool or capability request",
    rationale:
      "The instruction text asks for capabilities that are not declared in the skill's frontmatter tool scope.",
    remediation: "Declare every tool the skill uses, or stop using it.",
    pattern:
      /\b(use\s+the\s+(bash|shell|terminal|browser|computer)\s+tool|run\s+(a\s+)?(shell|bash)\s+command|execute\s+the\s+following\s+(command|script))\b/i,
  },
  {
    id: "PGR-B009",
    layer: "behavioral",
    severity: "high",
    title: "Reads conversation or agent memory for export",
    rationale:
      "Harvesting chat history, memory files, or transcripts is the collection stage of an exfiltration chain.",
    remediation: "Remove the history read, or keep the data strictly local to the answer.",
    pattern:
      /\b(conversation\s+history|chat\s+history|full\s+transcript|previous\s+messages|memory\s+file|\.claude\/|CLAUDE\.md|\.cursor\/|\.config\/[a-z]*ai)\b[^.\n]{0,60}\b(send|post|upload|copy|share|include|attach|transmit)\b/i,
  },
  {
    id: "PGR-B010",
    layer: "behavioral",
    severity: "medium",
    title: "Reverse shell or raw socket listener",
    rationale: "Interactive remote access has no legitimate place inside a documentation-driven skill.",
    remediation: "Remove the listener.",
    pattern:
      /\b(nc\s+-[a-z]*l[a-z]*\s|ncat\s+.*--exec|bash\s+-i\s*>&\s*\/dev\/tcp|socket\.socket\([^)]*\)[^\n]*connect|telnet\s+\d)/i,
  },
  {
    id: "PGR-B011",
    layer: "behavioral",
    severity: "medium",
    title: "Unrestricted file scan over user directories",
    rationale:
      "Recursive searches across home or root directories collect far more than any single task requires.",
    remediation: "Scope reads to the working directory or explicit paths.",
    pattern:
      /\b(find\s+(\/|~|\$HOME)\s|grep\s+-r[a-z]*\s+[^\n]{0,40}\s+(\/|~|\$HOME)\b|ls\s+-[a-zR]*R[a-zR]*\s+(\/|~))/i,
  },

  // ── Layer 3: provenance & supply chain ──────────────────────────────────
  {
    id: "PGR-P001",
    layer: "provenance",
    severity: "high",
    title: "Unpinned dependency installation",
    rationale:
      "Installing a package at latest resolves to whatever the registry serves at run time, which is not what was reviewed.",
    remediation: "Pin exact versions and, where possible, integrity hashes.",
    pattern:
      /\b((npm|bun|pnpm|yarn)\s+(i|add|install)|pip\s+install|gem\s+install|go\s+install)\s+(?![^\n]*[@=]\d)[^\n]{1,80}$/i,
  },
  {
    id: "PGR-P002",
    layer: "provenance",
    severity: "high",
    title: "Dependency pulled from a non-registry source",
    rationale:
      "Direct git, gist, or pastebin sources bypass registry scanning and can be rewritten after review.",
    remediation: "Publish the dependency to your registry or vendor it in.",
    pattern:
      /\b(pip\s+install\s+git\+|npm\s+i(nstall)?\s+(git\+|https?:\/\/)|gist\.githubusercontent|pastebin\.com|paste\.ee|transfer\.sh|file\.io|anonfiles)/i,
  },
  {
    id: "PGR-P003",
    layer: "provenance",
    severity: "medium",
    title: "Hardcoded credential or API key",
    rationale:
      "A live secret embedded in a distributed skill is disclosed to every recipient of the artifact.",
    remediation: "Move the secret to a runtime secret store and rotate the exposed value.",
    pattern:
      /\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN\s+[A-Z ]*PRIVATE\s+KEY-----)/,
  },
  {
    id: "PGR-P004",
    layer: "provenance",
    severity: "medium",
    title: "Executable or binary artifact bundled with the skill",
    rationale:
      "Compiled artifacts cannot be reviewed as text and are a common carrier for the actual payload.",
    remediation: "Ship source, not binaries, or move the binary behind a signed internal registry.",
    pattern: /^\uFFFF$/, // evaluated structurally in the engine
    pathPattern: /\.(exe|dll|so|dylib|bin|jar|pyc|wasm|scpt|app|msi|deb|rpm)$/i,
  },
  {
    id: "PGR-P005",
    layer: "provenance",
    severity: "low",
    title: "Unattributed skill",
    rationale: "No author, license, or source repository is declared, so the skill cannot be traced.",
    remediation: "Add author, license, and repository fields to the frontmatter.",
    pattern: /^\uFFFF$/, // evaluated structurally in the engine
    pathPattern: /^\uFFFF$/,
  },

  // ── Layer 4: network posture ────────────────────────────────────────────
  {
    id: "PGR-N001",
    layer: "network",
    severity: "critical",
    title: "Outbound transmission of local data",
    rationale:
      "The skill sends local file or environment contents to a remote endpoint — the exfiltration stage itself.",
    remediation: "Remove the upload, or route it through an approved, logged internal service.",
    pattern:
      /\b(curl|wget|fetch|requests\.post|axios\.post|http\.post|Invoke-RestMethod)\b[^\n]{0,200}\b(-d\s|--data|@\/|body|json\s*=|-F\s|process\.env|os\.environ|\.env\b|cat\s)/i,
  },
  {
    id: "PGR-N002",
    layer: "network",
    severity: "high",
    title: "Hardcoded raw IP endpoint",
    rationale:
      "A literal IP address bypasses DNS-based allowlisting and monitoring and is characteristic of command-and-control.",
    remediation: "Use an approved, resolvable hostname on your egress allowlist.",
    pattern: /https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?/,
  },
  {
    id: "PGR-N003",
    layer: "network",
    severity: "high",
    title: "Anonymising or tunnelling endpoint",
    rationale: "Tunnels and disposable hosts are used to evade egress inspection and attribution.",
    remediation: "Remove the tunnel; call approved endpoints directly.",
    pattern:
      /\b([a-z0-9-]+\.)?(ngrok\.(io|app|dev)|trycloudflare\.com|localtunnel\.me|loca\.lt|serveo\.net|requestbin|webhook\.site|pipedream\.net|burpcollaborator|oast\.(fun|live|site)|interact\.sh)\b/i,
  },
  {
    id: "PGR-N004",
    layer: "network",
    severity: "medium",
    title: "Data sent to a webhook or chat relay",
    rationale:
      "Generic webhook relays are a low-friction drop point for stolen data and are rarely on an egress allowlist.",
    remediation: "Replace with an approved internal endpoint.",
    pattern:
      /https?:\/\/[^\s"']{0,80}(hooks\.slack\.com|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|zapier\.com\/hooks|hooks\.zapier)/i,
  },
  {
    id: "PGR-N005",
    layer: "network",
    severity: "medium",
    title: "Data-carrying image or link beacon",
    rationale:
      "Encoding data in a URL rendered as an image or link exfiltrates silently at render time.",
    remediation: "Remove the beacon.",
    pattern:
      /!\[[^\]]{0,40}\]\(\s*https?:\/\/[^)\s]{0,200}[?&][a-z0-9_]{1,20}=\$?\{?[^)\s]{0,80}\)|<img[^>]{0,200}src\s*=\s*["']https?:\/\/[^"']{0,200}[?&]/i,
  },
  {
    id: "PGR-N006",
    layer: "network",
    severity: "medium",
    title: "Insecure plaintext transport",
    rationale: "http:// traffic can be read and rewritten in transit.",
    remediation: "Use https for every external call.",
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[a-z0-9.-]+/i,
  },
  {
    id: "PGR-N007",
    layer: "network",
    severity: "medium",
    title: "TLS verification disabled",
    rationale: "Skipping certificate checks removes the only defence against interception.",
    remediation: "Re-enable certificate verification.",
    pattern:
      /\b(curl[^\n]{0,60}\s(-k|--insecure)\b|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)/,
  },
  {
    id: "PGR-N008",
    layer: "network",
    severity: "low",
    title: "Undeclared external endpoint",
    rationale:
      "Every external host the skill contacts should be reviewable against your egress allowlist.",
    remediation: "Document each endpoint and confirm it is allowlisted.",
    pattern: /^\uFFFF$/, // evaluated structurally in the engine (endpoint inventory)
    pathPattern: /^\uFFFF$/,
  },
];

export const LAYER_LABEL: Record<Layer, string> = {
  static: "Static analysis",
  behavioral: "Behavioral trace",
  provenance: "Provenance",
  network: "Network posture",
};

/** Rule IDs evaluated structurally by the engine rather than by line matching. */
export const STRUCTURAL_RULE_IDS = ["PGR-S011", "PGR-P004", "PGR-P005", "PGR-N008"] as const;

export const RULES_BY_ID: Record<string, Rule> = Object.fromEntries(
  RULES.map((r) => [r.id, r]),
);

/** Rules evaluated by line-matching. */
export const LINE_RULES = RULES.filter(
  (r) => !(STRUCTURAL_RULE_IDS as readonly string[]).includes(r.id),
);
