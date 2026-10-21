import { describe, expect, it } from "vitest";
import { formatSecret, passwordProblem, usernameProblem } from "./registerRules";

describe("usernameProblem", () => {
  it("accepts 3 to 32 letters, digits, dots and underscores", () => {
    for (const name of ["abc", "voter.one", "Voter_2", "a".repeat(32), "  padded  "]) {
      expect(usernameProblem(name)).toBe("");
    }
  });

  it("rejects names that are too short, too long or use other characters", () => {
    for (const name of ["ab", "a".repeat(33), "has space", "no-hyphen", "email@example.com", ""]) {
      expect(usernameProblem(name)).not.toBe("");
    }
  });
});

describe("passwordProblem", () => {
  it("needs 12 characters and nothing else", () => {
    expect(passwordProblem("x".repeat(11), "voter")).not.toBe("");
    expect(passwordProblem("x".repeat(12), "voter")).toBe("");
    expect(passwordProblem("all lowercase words", "voter")).toBe("");
  });

  it("counts characters, not UTF-16 units", () => {
    // Six characters but twelve UTF-16 units, so still too short
    expect(passwordProblem("😀".repeat(6), "voter")).not.toBe("");
  });

  it("refuses the username as the password, ignoring case", () => {
    expect(passwordProblem("Long.Username1", "long.username1")).not.toBe("");
  });
});

describe("formatSecret", () => {
  it("splits the setup key into groups of four", () => {
    expect(formatSecret("JBSWY3DPEHPK3PXP")).toBe("JBSW Y3DP EHPK 3PXP");
    expect(formatSecret("ABCDEF")).toBe("ABCD EF");
  });
});
