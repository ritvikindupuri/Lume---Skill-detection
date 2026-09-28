import { createFileRoute } from "@tanstack/react-router";
import { createClient } from "@supabase/supabase-js";
import { streamText } from "ai";
import { z } from "zod";
import {
  AI_MODEL,
  AI_SYSTEM_PROMPT,
  aiUserPrompt,
  extractJson,
  normalizeFindings,
  normalizeRecommendation,
} from "@/lib/ai-findings";

const bodySchema = z.object({
  artifactName: z.string().min(1).max(255),
  content: z.string().min(1).max(500_000),
  deterministicFindings: z
    .array(
      z.object({
        ruleId: z.string(),
        title: z.string(),
        severity: z.enum(["critical", "high", "medium", "low"]),
        file: z.string(),
        line: z.number(),
        evidence: z.string(),
      }),
    )
    .max(200),
});

async function authorize(request: Request): Promise<boolean> {
  const url = process.env["SUPABASE_URL"];
  const key = process.env["SUPABASE_PUBLISHABLE_KEY"];
  const header = request.headers.get("authorization") ?? "";
  if (!url || !key || !header.startsWith("Bearer ")) return false;
  const token = header.slice(7);
  if (token.split(".").length !== 3) return false;
  const supabase = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data, error } = await supabase.auth.getClaims(token);
  return !error && Boolean(data?.claims?.sub);
}

function getAllowedOrigins(): string[] {
  const envOrigins = process.env["ALLOWED_ORIGINS"];
  if (envOrigins) {
    return envOrigins.split(",").map((o) => o.trim());
  }
  return [];
}

function checkCors(request: Request): { allowed: boolean; origin?: string } {
  const origin = request.headers.get("origin");
  if (!origin) return { allowed: true };
  const allowedOrigins = getAllowedOrigins();
  if (allowedOrigins.length === 0) return { allowed: true };
  return { allowed: allowedOrigins.includes(origin), origin };
}

export const Route = createFileRoute("/api/ai-scan")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const cors = checkCors(request);
        if (!cors.allowed) {
          return new Response("Forbidden", { status: 403 });
        }

        if (!(await authorize(request))) return new Response("Unauthorized", { status: 401 });

        const parsed = bodySchema.safeParse(await request.json());
        if (!parsed.success) return new Response("Invalid request", { status: 400 });
        const data = parsed.data;

        const apiKey = process.env["OPENAI_API_KEY"];
        if (!apiKey)
          return new Response("OpenAI API key is not configured for this workspace.", {
            status: 500,
          });

        const { createLumeAi } = await import("@/lib/ai-gateway.server");
        const provider = createLumeAi(apiKey);

        const encoder = new TextEncoder();
        const stream = new ReadableStream<Uint8Array>({
          async start(controller) {
            const send = (event: Record<string, unknown>) =>
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
            try {
              const result = streamText({
                model: provider.responses(AI_MODEL),
                maxRetries: 2,
                providerOptions: {
                  openai: {
                    reasoningEffort: "high",
                    reasoningSummary: "detailed",
                    forceReasoning: true,
                    store: false,
                    include: ["reasoning.encrypted_content"],
                  },
                },
                system: AI_SYSTEM_PROMPT,
                prompt: aiUserPrompt(data.artifactName, data.deterministicFindings, data.content),
                abortSignal: request.signal,
              });

              let output = "";
              let streamed = 0;
              const flushLog = () => {
                // Everything before the JSON fence is the reviewer-facing reading log.
                const cut = output.indexOf("```");
                const visible = cut === -1 ? output : output.slice(0, cut);
                if (visible.length > streamed) {
                  send({ type: "reasoning", text: visible.slice(streamed) });
                  streamed = visible.length;
                }
              };
              for await (const part of result.fullStream) {
                if (part.type === "reasoning-delta") send({ type: "reasoning", text: part.text });
                else if (part.type === "text-delta") {
                  output += part.text;
                  flushLog();
                }
              }
              flushLog();
              const parsedJson = extractJson(output || (await result.text));
              send({
                type: "done",
                model: AI_MODEL,
                findings: normalizeFindings(parsedJson),
                recommendation: normalizeRecommendation(parsedJson),
              });
            } catch (error) {
              const status =
                typeof error === "object" && error && "statusCode" in error
                  ? Number(error.statusCode)
                  : undefined;
              const base = error instanceof Error ? error.message : "AI analysis failed.";
              const message =
                status === 402
                  ? `${base} Insufficient OpenAI quota or credits. Add credits to your OpenAI account to continue.`
                  : status === 403
                    ? `${base} AI access is blocked by policy.`
                    : status === 429
                      ? `${base} The OpenAI service is rate limited; try again shortly.`
                      : status === 401
                        ? "OpenAI API key is invalid or not configured correctly."
                        : base;
              send({ type: "error", message });
            } finally {
              controller.close();
            }
          },
        });

        return new Response(stream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache, no-transform",
            Connection: "keep-alive",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
          },
        });
      },
    },
  },
});
