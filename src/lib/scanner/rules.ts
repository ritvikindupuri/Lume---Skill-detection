export type Severity = "critical" | "high" | "medium" | "low";

export type Layer =
  | "prompt"
  | "agency"
  | "leakage"
  | "privacy"
  | "supply-chain"
  | "integrity"
  | "bias"
  | "resilience";

export interface Rule {
  id: string;
  layer: Layer;
  severity: Severity;
  title: string;
  rationale: string;
  remediation: string;
  pattern: RegExp;
  pathPattern?: RegExp;
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 18,
  medium: 7,
  low: 2,
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

const r = (
  id: string,
  layer: Layer,
  severity: Severity,
  title: string,
  rationale: string,
  remediation: string,
  pattern: RegExp,
  pathPattern?: RegExp,
): Rule => ({
  id,
  layer,
  severity,
  title,
  rationale,
  remediation,
  pattern,
  ...(pathPattern ? { pathPattern } : {}),
});

/**
 * 35 deterministic checks derived from OWASP Top 10 for LLM Applications,
 * MITRE ATLAS, and the NIST AI RMF Generative AI Profile. Each check is
 * executed against real artifact content; structural checks are identified
 * below and evaluated by the engine.
 */
export const RULES: Rule[] = [
  r(
    "ATT-001",
    "prompt",
    "critical",
    "Hidden instruction directive",
    "Instructions concealed in comments can reach the model while evading human review.",
    "Make every operative instruction visible or remove it.",
    /<!--[^>]{0,500}\b(ignore|always|must|system|secret|send|upload|execute|instruction)\b/i,
  ),
  r(
    "ATT-002",
    "prompt",
    "critical",
    "System or operator instruction override",
    "Attempts to supersede higher-priority instructions are direct prompt injection.",
    "Remove all instruction-override language.",
    /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,45}\b(previous|prior|above|system|operator|developer)\b[^.\n]{0,30}\b(instruction|prompt|rule|policy|message)/i,
  ),
  r(
    "ATT-003",
    "prompt",
    "critical",
    "Delegated remote instruction loading",
    "Fetching external text and treating it as instructions gives an unreviewed party control of the agent.",
    "Bundle and review required instructions locally; never execute fetched prose as policy.",
    /\b(fetch|download|read|retrieve|load)\b[^.\n]{0,80}\b(url|website|remote|endpoint|file)\b[^.\n]{0,80}\b(follow|execute|obey|treat|use)\b[^.\n]{0,30}\b(instruction|prompt|command)/i,
  ),
  r(
    "ATT-004",
    "prompt",
    "high",
    "Instruction payload disguised as an example",
    "Few-shot examples can smuggle commands that the model is told to reproduce as live behavior.",
    "Clearly mark examples as inert and remove override or execution language from them.",
    /\b(example|sample|demonstration)\b[^\n]{0,80}\b(copy exactly|repeat verbatim|must output|execute this|follow these instructions)/i,
  ),
  r(
    "ATT-005",
    "prompt",
    "high",
    "Dormant conditional trigger",
    "A secret phrase, date, or user attribute can activate hidden behavior after review.",
    "Remove covert triggers and document legitimate conditions explicitly.",
    /\b(if|when|whenever)\b[^\n]{0,80}\b(keyword|phrase|date|time|user|hostname|environment)\b[^\n]{0,100}\b(secretly|instead|override|ignore|activate|trigger|payload)/i,
  ),
  r(
    "ATT-006",
    "prompt",
    "high",
    "Cross-skill instruction tampering",
    "Changing other skills or shared agent instructions creates cross-context compromise.",
    "Restrict changes to this skill and require explicit review for shared configuration.",
    /\b(modify|rewrite|replace|override|delete|patch)\b[^\n]{0,60}\b(other|another|installed|global)\b[^\n]{0,40}\b(skill|SKILL\.md|CLAUDE\.md|instruction|prompt)/i,
  ),
  r(
    "ATT-007",
    "agency",
    "critical",
    "Unscoped command execution",
    "Shell or dynamic execution can turn natural-language instructions into arbitrary code.",
    "Use allowlisted operations in a sandbox and require approval.",
    /\b(eval\s*\(|exec\s*\(|new\s+Function\s*\(|os\.system\s*\(|child_process|subprocess\.(Popen|call|run)[^\n]*shell\s*=\s*True|Invoke-Expression|IEX\s*\()/i,
  ),
  r(
    "ATT-008",
    "agency",
    "critical",
    "Destructive operation",
    "Irreversible deletion, disk writes, or history rewrites can destroy data and evidence.",
    "Remove the operation or place it behind explicit human approval and a dry run.",
    /\brm\s+-[a-z]*[rf][a-z]*\s+(\/|~|\$HOME|\*)|\bgit\s+push\s+(--force|-f)\b|\bDROP\s+(TABLE|DATABASE|SCHEMA)\b|\bTRUNCATE\s+TABLE\b|\bmkfs\b|\bdd\s+if=.*of=\/dev\//i,
  ),
  r(
    "ATT-009",
    "agency",
    "high",
    "Autonomous network egress",
    "Unapproved outbound traffic can expose data or retrieve mutable instructions.",
    "Restrict egress to documented, allowlisted HTTPS hosts.",
    /\b(curl|wget|fetch\s*\(|axios\.|requests\.(get|post)|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,180}https?:\/\//i,
  ),
  r(
    "ATT-010",
    "agency",
    "critical",
    "Privilege escalation",
    "Elevated execution exceeds normal skill scope and increases blast radius.",
    "Run with least privilege and remove elevation requests.",
    /\b(sudo\s+(-S|su\b|-i\b)|pkexec|setuid|chmod\s+777|runas\s+\/user:administrator)\b/i,
  ),
  r(
    "ATT-011",
    "resilience",
    "medium",
    "Unbounded loop or recursive invocation",
    "Unbounded retries or self-invocation can exhaust tokens, compute, or tool quotas.",
    "Add a strict iteration, time, and cost limit.",
    /\b(while\s+true|for\s*\(\s*;;\s*\)|retry\s+(forever|indefinitely|until\s+success)|recursively\s+(call|invoke|repeat)|never\s+stop)\b/i,
  ),
  r(
    "ATT-012",
    "agency",
    "critical",
    "Human approval bypass",
    "Skipping confirmation removes the control point before consequential actions.",
    "Require explicit approval for destructive, financial, outbound, or privileged actions.",
    /\b(without|skip|bypass|no\s+need\s+for|do\s*not\s+ask\s+for)\b[^.\n]{0,30}\b(confirmation|approval|permission|consent|review)|\bauto[-\s]?approve\b/i,
  ),
  r(
    "ATT-013",
    "agency",
    "high",
    "Cross-boundary file access",
    "Absolute paths and traversal can expose data outside the declared workspace.",
    "Constrain file access to the working directory and reject traversal.",
    /(?:^|[\s"'`])(\.\.\/|\/etc\/|\/home\/|\/Users\/|~\/|\$HOME\/)[^\s"'`]*/i,
  ),
  r(
    "ATT-014",
    "leakage",
    "critical",
    "Covert exfiltration channel",
    "URL parameters, DNS, or rendered beacons can transmit data without an obvious upload.",
    "Remove the channel and use an approved, logged data path.",
    /(!\[[^\]]*\]\(https?:\/\/[^)]+[?&][^=]+=\$?\{?[^)]+\)|<img[^>]+src=["']https?:\/\/[^"']+[?&]|\b(nslookup|dig)\s+\$?\{?[^\s]+\}?\.)/i,
  ),
  r(
    "ATT-015",
    "leakage",
    "critical",
    "Credential or secret harvesting",
    "Reading secret stores is a common collection stage before exfiltration.",
    "Remove secret access and accept only explicit, scoped inputs.",
    /(\.env(?:\.[a-z]+)?\b|~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.kube\/config|\.npmrc|\.netrc|\.git-credentials|service[-_]account\.json|keychain)/i,
  ),
  r(
    "ATT-016",
    "leakage",
    "high",
    "Conversation or context telemetry",
    "Exporting full prompts, messages, or context can disclose confidential business information.",
    "Log only minimal, redacted operational metadata to approved systems.",
    /\b(send|upload|post|transmit|log)\b[^.\n]{0,80}\b(full\s+)?(conversation|chat\s+history|transcript|prompt|context|previous\s+messages)\b/i,
  ),
  r(
    "ATT-017",
    "privacy",
    "high",
    "Cross-session data reuse",
    "Persisting one person's context for another can cause tenant or user data leakage.",
    "Partition storage by organization and user; expire session data.",
    /\b(reuse|share|load|retrieve|remember|persist)\b[^.\n]{0,70}\b(previous|another|other)\b[^.\n]{0,35}\b(user|customer|session|tenant)('?s)?\b[^.\n]{0,40}\b(data|context|history|result)/i,
  ),
  r(
    "ATT-018",
    "leakage",
    "medium",
    "Broad sensitive file discovery",
    "Recursive scans of home or root directories collect more data than a skill needs.",
    "Scope file reads to explicit workspace paths.",
    /\b(find\s+(\/|~|\$HOME)\s|grep\s+-r[a-z]*\s+[^\n]{0,50}\s+(\/|~|\$HOME)|glob\s*\([^)]*\*\*\/\*|ls\s+-[a-zR]*R[a-zR]*\s+(\/|~))/i,
  ),
  r(
    "ATT-019",
    "privacy",
    "high",
    "Excessive personal or health data collection",
    "Collecting sensitive personal data without necessity violates data-minimization principles.",
    "Collect only fields required for the stated purpose and obtain consent.",
    /\b(collect|extract|gather|scrape|store|record)\b[^.\n]{0,80}\b(SSN|social\s+security|passport|medical|health\s+record|diagnosis|biometric|sexual\s+orientation|religion|ethnicity|home\s+address|date\s+of\s+birth)\b/i,
  ),
  r(
    "ATT-020",
    "privacy",
    "medium",
    "Personal data processing without retention limits",
    "Personal data without purpose and retention boundaries can be kept indefinitely or reused.",
    "Declare purpose, retention period, deletion, and access boundaries.",
    /\b(store|retain|archive|save|remember)\b[^.\n]{0,70}\b(personal|customer|employee|patient|user)\b[^.\n]{0,30}\b(data|information|profile|record)\b(?![^\n]{0,90}\b(delete|expire|retention|consent|purpose)\b)/i,
  ),
  r(
    "ATT-021",
    "privacy",
    "high",
    "Re-identification of anonymized data",
    "Joining quasi-identifiers can reverse anonymization and expose individuals.",
    "Prohibit re-identification and use privacy-preserving aggregation.",
    /\b(re-?identify|de-?anonymi[sz]e|reverse\s+anonymi[sz]ation|link\s+anonymous\s+records|correlate\s+identifiers)\b/i,
  ),
  r(
    "ATT-022",
    "privacy",
    "high",
    "Third-party personal data sharing without consent",
    "Sending personal data to another service without consent violates user expectations and privacy controls.",
    "Add informed consent and an approved processor agreement, or keep data local.",
    /\b(send|share|upload|transmit|provide)\b[^.\n]{0,70}\b(personal|customer|employee|patient|user)\b[^.\n]{0,30}\b(data|information|record)\b[^.\n]{0,70}\b(third[- ]party|vendor|partner|external\s+(api|service))\b/i,
  ),
  r(
    "ATT-023",
    "supply-chain",
    "critical",
    "Unpinned remote dependency",
    "Runtime installation from a mutable source can execute code that was never reviewed.",
    "Pin an exact version and integrity hash, or vendor reviewed source.",
    /\b((npm|bun|pnpm|yarn)\s+(i|add|install)|pip\s+install|gem\s+install|go\s+install)\s+(?![^\n]*[@=]\d)[^\n]{1,100}|\b(curl|wget)\b[^\n|]{0,160}\|\s*(sudo\s+)?(ba|z|k|d)?sh\b/i,
  ),
  r(
    "ATT-024",
    "supply-chain",
    "high",
    "Lookalike package reference",
    "Package names that mimic common dependencies are a known supply-chain delivery technique.",
    "Verify the package against the official registry and publisher.",
    /\b(reqeusts|requestss|lodahs|reactt|expresss|numpyy|pytorch-|openaii|anthropicc|colourama|python-dateutils)\b/i,
  ),
  r(
    "ATT-025",
    "supply-chain",
    "critical",
    "Self-modifying skill or agent configuration",
    "A skill that rewrites its own or global instructions can become persistent after approval.",
    "Make skills immutable at runtime and require reviewed updates.",
    /\b(write|append|modify|rewrite|patch|replace)\b[^\n]{0,70}\b(SKILL\.md|CLAUDE\.md|\.claude\/|agent\s+(config|instruction)|system\s+prompt)\b/i,
  ),
  r(
    "ATT-026",
    "supply-chain",
    "critical",
    "Obfuscated payload decoding",
    "Encoded payloads conceal the behavior that will actually execute.",
    "Replace encoded content with readable, reviewable source.",
    /\b(base64\s+(-{1,2}d(?:ecode)?)|atob\s*\(|b64decode|fromhex|Convert\.FromBase64String|rot13)\b|(?:^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{160,}={0,2}(?:$|[^A-Za-z0-9+/=])/i,
  ),
  r(
    "ATT-027",
    "supply-chain",
    "medium",
    "Unverifiable artifact provenance",
    "Missing authorship and licensing make ownership, review, and incident response harder.",
    "Declare an author, license, source repository, and release checksum.",
    /^\uFFFF$/,
    /^\uFFFF$/,
  ),
  r(
    "ATT-028",
    "supply-chain",
    "high",
    "Time-bomb or dormant backdoor",
    "Date and environment gates can conceal malicious behavior until after approval.",
    "Remove dormant activation logic and document all conditions.",
    /\b(after|before|on)\s+\d{4}[-/]\d{1,2}[-/]\d{1,2}\b[^\n]{0,90}\b(execute|activate|run|delete|send)|\b(time[- ]bomb|dormant\s+(payload|backdoor))\b/i,
  ),
  r(
    "ATT-029",
    "integrity",
    "medium",
    "Unsourced authoritative claims",
    "Directing the model to assert facts as certain without sources increases confabulation risk.",
    "Require attributable sources and calibrated uncertainty.",
    /\b(always\s+(state|claim|answer)|present\s+as\s+fact|assert\s+with\s+certainty|never\s+mention\s+uncertainty)\b[^\n]{0,90}\b(without\s+(sources|citation|verification)|even\s+if\s+unsure|regardless\s+of\s+evidence)/i,
  ),
  r(
    "ATT-030",
    "integrity",
    "high",
    "High-stakes advice without verification",
    "Medical, legal, or financial output without qualified review can cause material harm.",
    "Require authoritative sources, uncertainty disclosure, and qualified human review.",
    /\b(medical|diagnos|treatment|legal\s+advice|investment|financial\s+advice|credit\s+decision)\b[^\n]{0,120}\b(no\s+need\s+to|without)\b[^\n]{0,50}\b(verify|doctor|lawyer|advisor|professional|source|disclaimer|review)/i,
  ),
  r(
    "ATT-031",
    "integrity",
    "medium",
    "Fabricated tool or source instruction",
    "Telling the model to invent tools, citations, or API responses creates false evidence and failed calls.",
    "Use only declared tools and verifiable sources; fail clearly when unavailable.",
    /\b(invent|fabricate|make\s+up|simulate)\b[^.\n]{0,50}\b(citation|source|reference|API|tool|function|result|response)\b|\b(if\s+the\s+(tool|source|API)\s+(doesn'?t|does\s+not)\s+exist)[^.\n]{0,60}\b(pretend|invent|create)/i,
  ),
  r(
    "ATT-032",
    "bias",
    "medium",
    "Demographic stereotype in output guidance",
    "Hard-coded demographic assumptions can systematically skew generated output.",
    "Use neutral attributes and test outcomes across relevant groups.",
    /\b(all|most|typically|naturally)\b[^.\n]{0,35}\b(women|men|girls|boys|elderly|immigrants|disabled|[A-Za-z]+\s+people)\b[^.\n]{0,45}\b(are|prefer|cannot|should|good\s+at|bad\s+at|less|more)\b/i,
  ),
  r(
    "ATT-033",
    "bias",
    "high",
    "Protected-attribute decision rule",
    "Using protected traits in hiring, credit, housing, healthcare, or access decisions creates discrimination risk.",
    "Remove protected attributes from the decision rule and require fairness review.",
    /\b(reject|exclude|deny|rank\s+lower|prefer|filter\s+out|disqualify)\b[^.\n]{0,70}\b(race|ethnicity|gender|sex|religion|disability|age|pregnan|nationality|sexual\s+orientation)\b/i,
  ),
  r(
    "ATT-034",
    "resilience",
    "medium",
    "Unbounded context amplification",
    "Recursive expansion and unlimited ingestion can create denial of service and unpredictable cost.",
    "Set hard limits on files, bytes, tokens, retries, and recursion depth.",
    /\b(read|load|include|process|summarize)\b[^.\n]{0,70}\b(all|every|entire|unlimited)\b[^.\n]{0,50}\b(file|repository|internet|web|history|document)\b|\b(expand|repeat)\b[^.\n]{0,40}\b(recursively|until\s+complete|without\s+limit)/i,
  ),
  r(
    "ATT-035",
    "prompt",
    "critical",
    "Guardrail-bypass framing",
    "Fictional or research framing is being used to suppress safety boundaries.",
    "Remove the bypass request and keep safety policy active for every context.",
    /\b(for\s+(research|educational|fictional|hypothetical)\s+purposes|in\s+a\s+fictional\s+scenario)\b[^.\n]{0,100}\b(ignore|bypass|disable|circumvent|without)\b[^.\n]{0,40}\b(safety|policy|restriction|guardrail|filter|refusal)/i,
  ),
];

export const LAYER_LABEL: Record<Layer, string> = {
  prompt: "Prompt integrity",
  agency: "Agency & tools",
  leakage: "Data leakage",
  privacy: "Privacy",
  "supply-chain": "Supply chain",
  integrity: "Output integrity",
  bias: "Bias & fairness",
  resilience: "Resilience",
};

export const LAYERS = Object.keys(LAYER_LABEL) as Layer[];

export const STRUCTURAL_RULE_IDS = ["ATT-027"] as const;

export const RULES_BY_ID: Record<string, Rule> = Object.fromEntries(
  RULES.map((rule) => [rule.id, rule]),
);

export const LINE_RULES = RULES.filter(
  (rule) => !(STRUCTURAL_RULE_IDS as readonly string[]).includes(rule.id),
);

/**
 * Precision estimate for each check, expressed as a percentage. Base value
 * follows severity; checks whose pattern is broad (and therefore more likely
 * to match legitimate content) are lowered explicitly.
 */
const BASE_CONFIDENCE: Record<Severity, number> = { critical: 88, high: 78, medium: 68, low: 58 };

const CONFIDENCE_OVERRIDE: Record<string, number> = {
  "ATT-004": 62,
  "ATT-005": 60,
  "ATT-013": 45,
  "ATT-015": 55,
  "ATT-018": 55,
  "ATT-020": 48,
  "ATT-023": 60,
  "ATT-026": 58,
  "ATT-027": 92,
  "ATT-029": 60,
  "ATT-031": 62,
  "ATT-032": 50,
  "ATT-034": 52,
};

export function ruleConfidence(id: string, severity: Severity): number {
  return CONFIDENCE_OVERRIDE[id] ?? BASE_CONFIDENCE[severity];
}

export function confidenceLabel(confidence: number): string {
  if (confidence >= 80) return "High precision";
  if (confidence >= 60) return "Moderate precision";
  return "Broad heuristic";
}

/** A check authored inside the workspace and compiled to a runnable rule. */
export interface CustomCheckInput {
  code: string;
  title: string;
  severity: Severity;
  layer: Layer;
  pattern: string;
  rationale: string;
  remediation: string;
  confidence: number;
}

export function compileCustomCheck(check: CustomCheckInput): Rule | null {
  try {
    return {
      id: check.code,
      layer: check.layer,
      severity: check.severity,
      title: check.title,
      rationale: check.rationale || "Matched a check defined by this workspace.",
      remediation: check.remediation || "Review this pattern against your internal policy.",
      pattern: new RegExp(check.pattern, "i"),
    };
  } catch {
    return null;
  }
}
