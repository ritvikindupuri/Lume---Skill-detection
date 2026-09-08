import JSZip from "jszip";
import type { ArtifactFile } from "./engine";

const MAX_TOTAL_BYTES = 20 * 1024 * 1024;
const BINARY_EXT =
  /\.(exe|dll|so|dylib|bin|jar|pyc|wasm|scpt|app|msi|deb|rpm|png|jpg|jpeg|gif|webp|ico|pdf|zip|gz|tar|mp4|mp3|woff2?|ttf|otf)$/i;

function decode(bytes: Uint8Array, path: string): string | null {
  if (BINARY_EXT.test(path)) return null;
  const sample = bytes.subarray(0, 4096);
  for (const b of sample) if (b === 0) return null;
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

function relPath(file: File): string {
  const anyFile = file as File & { webkitRelativePath?: string };
  return anyFile.webkitRelativePath && anyFile.webkitRelativePath.length > 0
    ? anyFile.webkitRelativePath
    : file.name;
}

export class ArtifactError extends Error {}

export async function readArtifact(
  files: File[],
): Promise<{ name: string; files: ArtifactFile[] }> {
  if (files.length === 0) throw new ArtifactError("No files were provided.");

  const total = files.reduce((n, f) => n + f.size, 0);
  if (total > MAX_TOTAL_BYTES) {
    throw new ArtifactError("Artifact exceeds the 20 MB limit.");
  }

  const out: ArtifactFile[] = [];

  for (const file of files) {
    if (/\.zip$/i.test(file.name)) {
      const zip = await JSZip.loadAsync(await file.arrayBuffer());
      const entries = Object.values(zip.files).filter((e) => !e.dir);
      if (entries.length === 0) throw new ArtifactError(`${file.name} contains no files.`);
      let zipBytes = 0;
      for (const entry of entries) {
        const bytes = await entry.async("uint8array");
        zipBytes += bytes.byteLength;
        if (zipBytes > MAX_TOTAL_BYTES) {
          throw new ArtifactError("Uncompressed archive exceeds the 20 MB limit.");
        }
        out.push({
          path: entry.name,
          size: bytes.byteLength,
          text: decode(bytes, entry.name),
        });
      }
      continue;
    }

    const bytes = new Uint8Array(await file.arrayBuffer());
    out.push({ path: relPath(file), size: bytes.byteLength, text: decode(bytes, relPath(file)) });
  }

  const hasText = out.some((f) => f.text !== null);
  if (!hasText) {
    throw new ArtifactError("No readable text files found in this artifact.");
  }

  const rootName =
    files.length === 1
      ? files[0]!.name
      : (relPath(files[0]!).split("/")[0] ?? `${files.length} files`);

  return { name: rootName, files: out };
}

export async function readPastedSkill(text: string): Promise<{ name: string; files: ArtifactFile[] }> {
  if (!text.trim()) throw new ArtifactError("Paste the contents of a SKILL.md first.");
  return {
    name: "SKILL.md (pasted)",
    files: [{ path: "SKILL.md", size: new Blob([text]).size, text }],
  };
}
