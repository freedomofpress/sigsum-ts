import { describe, expect, it } from "vitest";

import {
  evalQuorumBytecode,
  importAndHashAll,
  parseCompiledPolicy,
} from "../compiledPolicy";
import { Uint8ArrayToHex } from "../encoding";

describe("compiledPolicy", () => {
  it("rejects unsupported versions and trailing data", () => {
    expect(() => parseCompiledPolicy(new Uint8Array([1, 0, 0, 0]))).toThrow(
      "unsupported compiled policy version",
    );
    expect(() => parseCompiledPolicy(new Uint8Array([0, 0, 0, 0, 1]))).toThrow(
      "trailing data",
    );
  });

  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])(
    "rejects the public key length %s",
    (length) => {
      expect(() =>
        parseCompiledPolicy(new Uint8Array([0, 0, 0, 0]), length),
      ).toThrow("invalid raw public key length");
    },
  );

  it("sorts keys by hash", async () => {
    const keys = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
    const hashed = await importAndHashAll(keys);
    const descending = hashed.map((entry) => entry.raw.bytes).reverse();
    const sorted = await importAndHashAll(descending);
    const hashes = sorted.map((entry) => Uint8ArrayToHex(entry.hash.bytes));
    expect(hashes).toEqual([...hashes].sort());
  });

  it("rejects duplicate witness keys", async () => {
    const key = new Uint8Array(32).fill(1);
    await expect(importAndHashAll([key, key])).rejects.toThrow(
      "duplicate public keys",
    );
  });

  it("rejects invalid bytecode prefixes", () => {
    const invalid = [
      [0xc0, 0x40],
      [0xc1, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0x40],
      [0x40, 0xc1],
    ];
    for (const bytecode of invalid) {
      expect(
        evalQuorumBytecode(
          new Uint8Array(bytecode),
          1,
          new Uint8Array([1]),
        ),
      ).toBe(false);
    }
  });
});
