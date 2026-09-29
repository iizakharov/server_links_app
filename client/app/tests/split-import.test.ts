import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeSplitEntries } from "../ui/lib/split-import.ts";

test("keeps manual edits, removes repeats and reports only new entries", () => {
  const current = ["manual.example", "Example.COM", "1.2.3.4", "1.2.3.4"];
  const imported = ["example.com", "1.2.3.4", "2001:db8::1", "10.0.0.0/8"];
  const result = mergeSplitEntries(current, imported);
  assert.deepEqual(result, {
    entries: ["manual.example", "Example.COM", "1.2.3.4", "2001:db8::1", "10.0.0.0/8"], added: 2,
  });
  assert.deepEqual(mergeSplitEntries(result.entries, imported), { entries: result.entries, added: 0 });
  const edited = [...result.entries, "later.example"];
  assert.deepEqual(mergeSplitEntries(edited, []), { entries: edited, added: 0 });
  assert.equal(current.length, 4);
});
