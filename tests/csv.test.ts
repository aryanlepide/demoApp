import assert from "node:assert/strict";
import { test } from "node:test";
import { createSafeCsv } from "../public/csv.js";

test("quotes CSV fields and neutralizes spreadsheet formulas", () => {
  const csv = createSafeCsv(
    ["File", "Masked example"],
    [["=HYPERLINK(\"https://example.test\")", "****, ****"]],
  );

  assert.equal(csv, '\uFEFF"File","Masked example"\r\n"\'=HYPERLINK(""https://example.test"")","****, ****"');
});

test("neutralizes formula prefixes after leading whitespace", () => {
  const csv = createSafeCsv(["File"], [["\t+1+1"]]);

  assert.equal(csv, '\uFEFF"File"\r\n"\'\t+1+1"');
});