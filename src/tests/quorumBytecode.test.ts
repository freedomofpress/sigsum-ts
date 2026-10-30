import { describe, expect, it } from "vitest";

import { evalQuorumBytecode, parseCompiledPolicy } from "../compiledPolicy.js";
import { parsePolicyText } from "../config.js";
import { compilePolicyFromParsed } from "../policyCompiler.js";
import { Base64KeyHash } from "../types.js";

const W = (id: number) => 0x40 | id; // witness reference, ids below 64
const K = (k: number) => 0x80 | k; // threshold, k below 64
const ADD = 0x01;
const P = (v: number) => 0xc0 | v; // prefix byte

const run = (code: number[], present: number[]) =>
  evalQuorumBytecode(
    new Uint8Array(code),
    present.length,
    new Uint8Array(present),
  );

describe("evalQuorumBytecode", () => {
  it("evaluates single witnesses, thresholds and nested groups", () => {
    expect(run([W(0)], [1])).toBe(true);
    expect(run([W(0)], [0])).toBe(false);
    // 2-of-3
    const twoOfThree = [W(0), W(1), ADD, W(2), ADD, K(2)];
    expect(run(twoOfThree, [1, 1, 0])).toBe(true);
    expect(run(twoOfThree, [1, 0, 1])).toBe(true);
    expect(run(twoOfThree, [1, 0, 0])).toBe(false);
    // all of (w0) and (1-of w1,w2)
    const nested = [W(0), W(1), W(2), ADD, K(1), ADD, K(2)];
    expect(run(nested, [1, 0, 1])).toBe(true);
    expect(run(nested, [0, 1, 1])).toBe(false);
    expect(run(nested, [1, 0, 0])).toBe(false);
  });

  it("decodes multi-byte witness ids and thresholds", () => {
    const present = new Array(70).fill(0);
    present[65] = 1;
    expect(run([P(1), W(1)], present)).toBe(true); // id 65 = 1 << 6 | 1
    expect(run([P(1), W(2)], present)).toBe(false); // id 66
    // threshold 64 (prefix-encoded) over 64 witnesses
    const code = [W(0)];
    for (let i = 1; i < 64; i++) code.push(W(i), ADD);
    code.push(P(1), K(0)); // k = 1 << 6 | 0
    expect(run(code, new Array(64).fill(1))).toBe(true);
    expect(run(code, [...new Array(63).fill(1), 0])).toBe(false);
  });

  it("fails closed on malformed bytecode instead of throwing", () => {
    const cases: number[][] = [
      [ADD], // underflow
      [W(0), ADD], // underflow
      [K(1)], // threshold with empty stack
      [W(0), W(1)], // two values left
      [W(0), P(1)], // trailing prefix
      [P(0), W(0)], // leading zero prefix
      [W(5)], // id beyond the witness count
      [0x02], // unknown special opcode
      [P(1), ADD], // prefix before ADD
      [0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, W(0)], // prefix overflow
    ];
    for (const code of cases) {
      expect(() => run(code, [1, 1])).not.toThrow();
      expect(run(code, [1, 1])).toBe(false);
    }
    expect(run([], [])).toBe(true);
  });

  it("rejects a sum that wraps past 255 instead of accepting a wrapped count", () => {
    // 256 references to one present witness summed: the count wraps to 0.
    const code: number[] = [W(0)];
    for (let i = 1; i < 256; i++) code.push(W(0), ADD);
    code.push(K(1));
    // bytecode length would be 512 > 255; evaluate directly to pin the overflow rule
    expect(run(code, [1])).toBe(false);
  });

  it("terminates on arbitrary bytecode", () => {
    let seed = 12345;
    const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) % 256;
    for (let n = 0; n < 2000; n++) {
      const len = rand() % 256;
      const code = Array.from({ length: len }, rand);
      const nw = 1 + (rand() % 8);
      const present = Array.from({ length: nw }, () => rand() % 2);
      expect(() => run(code, present)).not.toThrow();
    }
  });
});

describe("parseCompiledPolicy", () => {
  it("never throws anything but an Error on arbitrary input and never hangs", () => {
    let seed = 777;
    const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) % 256;
    for (let n = 0; n < 2000; n++) {
      const buf = new Uint8Array(Array.from({ length: rand() % 300 }, rand));
      try {
        parseCompiledPolicy(buf);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });
});

// The bytecode evaluator must agree with the text policy's own quorum
// evaluation for every combination of present witnesses.
describe("compiled and text policies agree", () => {
  const hex = (i: number) => (i + 1).toString(16).padStart(2, "0").repeat(32);

  async function check(policyText: string) {
    const policy = await parsePolicyText(policyText);
    const compiled = parseCompiledPolicy(await compilePolicyFromParsed(policy));
    // Witness order in the compiled policy is by key hash; map each slot to its key hash.
    const { importAndHashAll } = await import("../compiledPolicy.js");
    const slots = await importAndHashAll(compiled.witnessesRaw);
    const n = slots.length;
    for (let mask = 0; mask < 1 << n; mask++) {
      const present = new Uint8Array(n);
      const presentSet = new Set<Base64KeyHash>();
      for (let i = 0; i < n; i++) {
        if (mask & (1 << i)) {
          present[i] = 1;
          const match = [...policy.witnesses.keys()].find(
            (k) => k.value === slots[i].b64.value,
          );
          if (!match) throw new Error("witness not found");
          presentSet.add(match);
        }
      }
      expect(evalQuorumBytecode(compiled.quorum, n, present)).toBe(
        policy.quorum.isQuorum(presentSet),
      );
    }
  }

  it("for flat and nested quorums", async () => {
    const witnesses = Array.from(
      { length: 6 },
      (_, i) => `witness w${i} ${hex(i)}`,
    ).join("\n");
    const log = `log ${hex(99)}`;
    for (const quorum of [
      "quorum w0",
      "group g any w0 w1 w2\nquorum g",
      "group g all w0 w1 w2\nquorum g",
      "group g 2 w0 w1 w2 w3\nquorum g",
      "group a 1 w0 w1\ngroup b 2 w2 w3 w4\ngroup g all a b w5\nquorum g",
      "group a 2 w0 w1 w2\ngroup b 1 w3 w4\ngroup g 1 a b\nquorum g",
      "group a 1 w0\ngroup g 2 a w1 w2\nquorum g",
      "quorum none",
    ]) {
      await check(`${log}\n${witnesses}\n${quorum}\n`);
    }
  });
});
