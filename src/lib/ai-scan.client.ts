import { supabase } from "@/integrations/supabase/client";
import type { Finding } from "./scanner/engine";
import type { Severity } from "./scanner/rules";

export interface AiScanPayload {
  artifactName: string;
  content: string;
  deterministicFindings: { ruleId: string; title: string; severity: Severity; file: string; line: number; evidence: string }[];
}

/** Streams the GPT review, emitting reasoning text as it arrives. */
export async function streamAiScan(
  payload: AiScanPayload,
  onReasoning: (text: string) => void,
): Promise<{ model: string; findings: Finding[] }> {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new Error("Your session expired. Sign in again.");

  const response = await fetch("/api/ai-scan", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  if (!response.ok || !response.body) throw new Error(await response.text().catch(() => "AI analysis failed."));

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result: { model: string; findings: Finding[] } | null = null;
  let failure: string | null = null;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop() ?? "";
    for (const chunk of chunks) {
      const line = chunk.split("\n").find((item) => item.startsWith("data: "));
      if (!line) continue;
      const event = JSON.parse(line.slice(6)) as { type: string; text?: string; message?: string; model?: string; findings?: Finding[] };
      if (event.type === "reasoning" && event.text) onReasoning(event.text);
      else if (event.type === "done") result = { model: event.model ?? "openai/gpt-6-astra", findings: event.findings ?? [] };
      else if (event.type === "error") failure = event.message ?? "AI analysis failed.";
    }
  }

  if (failure) throw new Error(failure);
  if (!result) throw new Error("The AI review ended before returning a verdict.");
  return result;
}
