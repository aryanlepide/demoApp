export type SensitiveDataType = "email" | "uk_phone" | "uk_nino" | "payment_card";
export type RiskLevel = "None" | "Low" | "Medium" | "High" | "Critical";

export interface Finding {
  type: SensitiveDataType;
  risk: Exclude<RiskLevel, "None">;
  count: number;
  maskedExample: string;
}

export interface ScanResult {
  risk: RiskLevel;
  findings: Finding[];
}

interface Candidate {
  start: number;
  end: number;
  type: SensitiveDataType;
  value: string;
}

const risks: Record<SensitiveDataType, Exclude<RiskLevel, "None">> = {
  email: "Low",
  uk_phone: "Medium",
  uk_nino: "High",
  payment_card: "Critical",
};

const riskOrder: Record<RiskLevel, number> = {
  None: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const patterns: Array<[SensitiveDataType, RegExp]> = [
  [
    "email",
    /(?<![A-Z0-9._%+-])[A-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+(?![A-Z0-9-]|\.[A-Z0-9])/giu,
  ],
  [
    "uk_phone",
    /(?<![\w+])(?:\+44|0)(?:[ \t().-]*\d){9,10}(?![\w])/g,
  ],
  [
    "uk_nino",
    /(?<![A-Z0-9])(?!(?:BG|GB|KN|NK|NT|TN|ZZ))[A-CEG-HJ-PR-TW-Z][A-CEG-HJ-NPR-TW-Z](?:[ \t]*\d{2}){3}[ \t]*[A-D]?(?![A-Z0-9])/gi,
  ],
  ["payment_card", /(?<!\d)(?<!\d[ -])\d(?:[ -]?\d){12,18}(?![ -]?\d)/g],
];

function isValidUkPhone(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  const nationalNumber = value.startsWith("+44") ? `0${digits.slice(2)}` : digits;

  return /^07[1-57-9]\d{8}$/.test(nationalNumber)
    || /^0(?:1\d{8,9}|2\d{9})$/.test(nationalNumber);
}

function passesLuhn(value: string): boolean {
  const digits = value.replace(/[ -]/g, "");
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }

  let sum = 0;
  let doubleDigit = false;

  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    doubleDigit = !doubleDigit;
  }

  return sum % 10 === 0;
}

function mask(type: SensitiveDataType, value: string): string {
  switch (type) {
    case "email":
      return "***@***";
    case "uk_phone":
      return `***-${value.replace(/\D/g, "").slice(-4)}`;
    case "uk_nino":
      return "** ** ** ** *";
    case "payment_card":
      return `**** **** **** ${value.replace(/[ -]/g, "").slice(-4)}`;
  }
}

function collectCandidates(content: string): Candidate[] {
  const candidates: Candidate[] = [];

  for (const [type, pattern] of patterns) {
    for (const match of content.matchAll(pattern)) {
      const value = match[0];
      if (type === "uk_phone" && !isValidUkPhone(value)) {
        continue;
      }
      if (type === "payment_card" && !passesLuhn(value)) {
        continue;
      }

      candidates.push({
        start: match.index,
        end: match.index + value.length,
        type,
        value,
      });
    }
  }

  return candidates.sort((left, right) =>
    left.start - right.start
    || right.end - left.end
    || riskOrder[risks[right.type]] - riskOrder[risks[left.type]],
  );
}

export function analyzeText(content: string): ScanResult {
  if (typeof content !== "string") {
    throw new TypeError("Detection input must be text.");
  }

  const counts = new Map<SensitiveDataType, { count: number; maskedExample: string }>();
  let lastAcceptedEnd = -1;

  for (const candidate of collectCandidates(content)) {
    if (candidate.start < lastAcceptedEnd) {
      continue;
    }
    lastAcceptedEnd = candidate.end;

    const existing = counts.get(candidate.type);
    if (existing) {
      existing.count += 1;
    } else {
      counts.set(candidate.type, {
        count: 1,
        maskedExample: mask(candidate.type, candidate.value),
      });
    }
  }

  const findings = Array.from(counts, ([type, aggregate]) => ({
    type,
    risk: risks[type],
    ...aggregate,
  })).sort((left, right) => riskOrder[right.risk] - riskOrder[left.risk]);

  const risk = findings.reduce<RiskLevel>(
    (highest, finding) => riskOrder[finding.risk] > riskOrder[highest] ? finding.risk : highest,
    "None",
  );

  return { risk, findings };
}