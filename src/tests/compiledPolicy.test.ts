import { describe, expect, it } from "vitest";

import { importAndHashAll } from "../compiledPolicy";

describe("compiledPolicy", () => {
  it("rejects duplicate witness keys", async () => {
    const key = new Uint8Array(32).fill(1);
    await expect(importAndHashAll([key, key])).rejects.toThrow(
      "duplicate public keys",
    );
  });
});
