import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { analyzeText } from "../src/detector.ts";

interface ExpectedFixture {
  file: string;
  expected_file_risk: string;
  purpose: string;
}

const fixtureDirectory = new URL("./fixtures/additional/", import.meta.url);
const expectedFixtures = JSON.parse(
  readFileSync(new URL("EXPECTED_RESULTS.json", fixtureDirectory), "utf8"),
) as ExpectedFixture[];

function fixtureText(fileName: string): string {
  return readFileSync(new URL(fileName, fixtureDirectory), "utf8");
}

function findingCount(fileName: string, type: string): number | undefined {
  return analyzeText(fixtureText(fileName)).findings.find((finding) => finding.type === type)?.count;
}

test("matches intended risk for supported synthetic fixtures", () => {
  for (const fixture of expectedFixtures) {
    if (fixture.expected_file_risk === "Reject") {
      continue;
    }

    assert.equal(analyzeText(fixtureText(fixture.file)).risk, fixture.expected_file_risk, fixture.file);
  }
});

test("assigns the required risk to each detector type", () => {
  assert.equal(analyzeText(fixtureText("03_one_email.txt")).findings[0]?.risk, "Low");
  assert.equal(analyzeText(fixtureText("07_one_mobile.txt")).findings[0]?.risk, "Medium");
  assert.equal(analyzeText(fixtureText("12_nino_spaced.txt")).findings[0]?.risk, "High");
  assert.equal(analyzeText(fixtureText("17_valid_card_spaced.txt")).findings[0]?.risk, "Critical");
});

test("counts repeated, non-overlapping matches by type", () => {
  assert.equal(findingCount("04_many_emails.csv", "email"), 2);
  assert.equal(findingCount("05_repeated_email.txt", "email"), 2);
  assert.equal(findingCount("23_repeated_cards.txt", "payment_card"), 2);
});

test("uses the highest risk when findings are mixed", () => {
  const result = analyzeText(fixtureText("22_all_four.csv"));

  assert.equal(result.risk, "Critical");
  assert.deepEqual(result.findings.map((finding) => finding.risk), ["Critical", "High", "Medium", "Low"]);
});

test("returns only masked examples", () => {
  const result = analyzeText(fixtureText("22_all_four.csv"));
  const serialized = JSON.stringify(result);

  for (const rawMatch of [
    "alex@example.test",
    "07700 900123",
    "AB 12 34 56 C",
    "4111 1111 1111 1111",
  ]) {
    assert.equal(serialized.includes(rawMatch), false);
  }
  assert.ok(result.findings.every((finding) => finding.maskedExample.length > 0));
});

test("rejects partial phone, NINO, and card candidates", () => {
  for (const content of [
    "x07700 9001234",
    "XAB123456C",
    "AB123456CE",
    "FA123456A",
    "AF123456A",
    "4111 1111 1111 1111 9",
  ]) {
    assert.equal(analyzeText(content).risk, "None");
  }
});

test("returns None for empty or clean text", () => {
  assert.deepEqual(analyzeText("") , { risk: "None", findings: [] });
  assert.equal(analyzeText(fixtureText("01_clean_notes.txt")).risk, "None");
});