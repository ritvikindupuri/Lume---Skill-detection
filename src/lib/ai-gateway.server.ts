import { createOpenAI } from "@ai-sdk/openai";

export function createLumeAi(apiKey: string) {
  return createOpenAI({
    apiKey,
  });
}