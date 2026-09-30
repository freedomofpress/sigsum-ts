import { describe, expect, it } from "vitest";

import { Hash, KeyHash, Leaf, Signature } from "../types.js";

describe("Leaf", () => {
  it("returns raw bytes for auditing", () => {
    const checksum = new Hash(new Uint8Array([...Array(32).keys()]));
    const signature = new Signature(
      new Uint8Array([...Array(64).keys()].map((i) => (i + 32) % 256)),
    );
    const keyHash = new KeyHash(
      new Uint8Array([...Array(32).keys()].map((i) => (i + 96) % 256)),
    );

    const leaf = new Leaf(checksum, signature, keyHash);
    const raw = leaf.toBytes();

    const expected = new Uint8Array(1 + 32 + 64 + 32);
    expected[0] = 0x0;
    expected.set(checksum.bytes, 1);
    expected.set(signature.bytes, 1 + 32);
    expected.set(keyHash.bytes, 1 + 32 + 64);

    expect(raw).toEqual(expected);
    expect(raw.byteLength).toBe(129);
  });
});
