# Sample Claude Skills for Testing

This directory contains realistic Claude `SKILL.md` test artifacts designed to evaluate Lume's detection capabilities across different threat levels, rule categories, and AI review behaviors.

---

## Test Skill Catalog

| Test Skill                                                                    | Primary Threats & Rules Tested                                                                                                                          | Expected Verdict                           | Expected Score             |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | -------------------------- |
| **[clean-git-assistant](./clean-git-assistant/SKILL.md)**                     | Safe instructions, proper frontmatter metadata (`name`, `author`, `license`, `tools`), bounded actions.                                                 | **clean**                                  | 0 / 100                    |
| **[suspicious-log-parser](./suspicious-log-parser/SKILL.md)**                 | External telemetry endpoint (`ATT-009`), broad log file scanning (`ATT-018`), unpinned package suggestion (`ATT-023`).                                  | **suspicious**                             | ~25–40 / 100 (Review band) |
| **[malicious-prompt-override](./malicious-prompt-override/SKILL.md)**         | Hidden HTML directives (`ATT-001`), operator instruction override (`ATT-002`), guardrail bypass framing (`ATT-035`), missing provenance (`ATT-027`).    | **malicious**                              | 80+ / 100                  |
| **[critical-credential-harvester](./critical-credential-harvester/SKILL.md)** | Secret harvesting (`ATT-015`), covert DNS/webhook exfiltration (`ATT-014`), unscoped `eval()` execution (`ATT-007`), human approval bypass (`ATT-012`). | **malicious** (Auto-blocked & Quarantined) | 90+ / 100                  |
| **[supply-chain-obfuscated](./supply-chain-obfuscated/SKILL.md)**             | Base64 payload decoding (`ATT-026`), lookalike packages (`ATT-024`), dormant time triggers (`ATT-028`), self-modifying agent config (`ATT-025`).        | **malicious**                              | 85+ / 100                  |

---

## How to Test in Lume

1. Navigate to your Lume dashboard (**Overview** tab).
2. Click **Scan multiple skills**.
3. Select any of the `SKILL.md` files from the subdirectories above (or select all 5 at once for batch scanning).
4. Observe:
   - Live deterministic rule matching in milliseconds.
   - Real-time streamed GPT reasoning in the **Thinking Log**.
   - Immediate risk score calculation, verdict classification, and automatic quarantine enforcement on critical findings.
