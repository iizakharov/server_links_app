/** Keep manual edits and their order when adding entries from a validated file. */
export function mergeSplitEntries(current: string[], imported: string[]) {
  const merged = new Map(current.map((entry) => [entry.toLowerCase(), entry]));
  const before = merged.size;
  for (const entry of imported) {
    if (!merged.has(entry.toLowerCase())) merged.set(entry.toLowerCase(), entry);
  }
  return { entries: [...merged.values()], added: merged.size - before };
}
