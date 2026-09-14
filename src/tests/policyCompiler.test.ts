import { describe, expect, it } from "vitest";

import { Uint8ArrayToHex } from "../encoding";
import { compilePolicy } from "../policyCompiler";

const SAMPLE_POLICY = `
log 1111111111111111111111111111111111111111111111111111111111111111

witness X1 2222222222222222222222222222222222222222222222222222222222222222
witness X2 3333333333333333333333333333333333333333333333333333333333333333
witness X3 4444444444444444444444444444444444444444444444444444444444444444
group X-witnesses 2 X1 X2 X3

witness Y1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
witness Y2 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
witness Y3 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
group Y-witnesses any Y1 Y2 Y3

group X-and-Y all X-witnesses Y-witnesses
quorum X-and-Y
`;

const EXPECTED_HEX =
  "0001060e1111111111111111111111111111111111111111111111111111111111111111bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb22222222222222222222222222222222222222222222222222222222222222224444444444444444444444444444444444444444444444444444444444444444cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc3333333333333333333333333333333333333333333333333333333333333333aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4043014501814142014401820182";

describe("policyCompiler", () => {
  it("matches the sigsum-c reference compiler output", async () => {
    const compiled = await compilePolicy(SAMPLE_POLICY);
    expect(Uint8ArrayToHex(compiled)).toBe(EXPECTED_HEX);
  });

  it("compiles a policy with no witness quorum", async () => {
    const compiled = await compilePolicy(`
      log ${"11".repeat(32)}
      quorum none
    `);
    expect(compiled[2]).toBe(0);
    expect(compiled[3]).toBe(0);
    expect(compiled).toHaveLength(36);
  });

  it("throws on syntax errors", async () => {
    const malformed = `
      log 1111111111111111111111111111111111111111111111111111111111111111
      wtness badkeyword 2222222222222222222222222222222222222222222222222222222222222222
    `;
    await expect(compilePolicy(malformed)).rejects.toThrow(/Unknown keyword/i);
  });

  it("throws on missing arguments", async () => {
    const incomplete = `
      witness OnlyName
      quorum
    `;
    await expect(compilePolicy(incomplete)).rejects.toThrow(
      /line must include/i,
    );
  });

  it("throws on undefined group reference", async () => {
    const badRef = `
      log ${"11".repeat(32)}
      witness A ${"22".repeat(32)}
      group invalidGroup 1 A B
      quorum invalidGroup
    `;
    await expect(compilePolicy(badRef)).rejects.toThrow(/undefined|unknown/i);
  });

  it("throws on duplicate witness name", async () => {
    const dupes = `
      log ${"11".repeat(32)}
      witness X ${"22".repeat(32)}
      witness X ${"33".repeat(32)}
      quorum X
    `;
    await expect(compilePolicy(dupes)).rejects.toThrow(/duplicate/i);
  });

  it("throws on too many logs", async () => {
    const hex = (n: number) => n.toString(16).padStart(64, "0");

    const tooMany = `
    ${Array.from({ length: 300 }, (_, i) => `log ${hex(i + 1)}`).join("\n")}
    witness A ${hex(301)}
    quorum A
  `;

    // Be permissive on the message; different builds may phrase it differently.
    await expect(compilePolicy(tooMany)).rejects.toThrow(
      /log|logs|at most|too many/i,
    );
  });
  it("throws on too many witnesses", async () => {
    const manyWitnesses = `
      log ${"11".repeat(32)}
      ${Array.from(
        { length: 300 },
        (_, i) => `witness W${i} ${i.toString(16).padStart(64, "0")}`,
      ).join("\n")}
      quorum W0
    `;

    await expect(compilePolicy(manyWitnesses)).rejects.toThrow(/at most/i);
  });

  it("throws on too long bytecode", async () => {
    const huge = `
    log ${"11".repeat(32)}
      ${Array.from(
        { length: 200 },
        (_, i) => `witness W${i} ${i.toString(16).padStart(64, "0")}`,
      ).join("\n")}
        group g any ${Array.from({ length: 200 }, (_, i) => `W${i}`).join(" ")}
        quorum g
    `;
    await expect(compilePolicy(huge)).rejects.toThrow(
      /Policy quorum too complex/i,
    );
  });

  it("covers add-and-sort branch when member bytecode size increases", async () => {
    const w = Array.from({ length: 70 }, (_, i) => {
      const hex = i.toString(16).padStart(64, "0");
      return `witness W${i} ${hex}`;
    }).join("\n");

    const members = Array.from({ length: 70 }, (_, i) => `W${i}`).join(" ");

    const policy = `
      log ${"11".repeat(32)}
      ${w}
      group g any ${members}
      quorum g
    `;

    const compiled = await compilePolicy(policy);

    expect(compiled).toBeInstanceOf(Uint8Array);
    expect(compiled.length).toBeGreaterThan(4 + 32 * (1 + 70));
    expect(compiled[3]).toBeGreaterThan(0);
  });
});
