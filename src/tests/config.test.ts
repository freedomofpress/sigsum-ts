import { describe, expect, it } from "vitest";

import { parsePolicyText } from "../config";

const log1 = "4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6";
const log2 = "0ec7e16843119b120377a73913ac6acbc2d03d82432e2c36b841b09a95841f25";

const witnesses = {
  nisse: "1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c",
  rgdd: "28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806",
  smartit: "f4855a0f46e8a3e23bb40faf260ee57ab8a18249fa402f2ca2d28a60e1a3130e",
  glasklar: "b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536",
  mullvad: "15d6d0141543247b74bab3c1076372d9c894f619c376d64b29aa312cc00f61ad",
};

describe("config", () => {
  it("parses a complex policy correctly without nested groups", async () => {
    const text = `
        log ${log1} https://test.sigsum.org/barreleye
        log ${log2} https://seasalp.glasklar.is

        witness test-nisse         ${witnesses.nisse}
        witness test-rgdd          ${witnesses.rgdd}
        witness test-smartit       ${witnesses.smartit}

        witness prod-glasklar      ${witnesses.glasklar}
        witness prod-mullvad       ${witnesses.mullvad}

        group test-majority 2 test-nisse test-rgdd test-smartit
        group prod-strict all prod-glasklar prod-mullvad

        group mixed-witnesses all test-majority prod-strict

        quorum mixed-witnesses`;
    const policy = await parsePolicyText(text);

    expect(policy.logs.size).toBe(2);
    expect(policy.witnesses.size).toBe(5);
    expect(policy.quorum).toBeDefined();
  });

  it("correctly parses a realistic Sigsum policy using any/all/k-of-n", async () => {
    const text = `
        log ${log1} https://test.sigsum.org/barreleye
        log ${log2} https://seasalp.glasklar.is

        witness nisse         ${witnesses.nisse}
        witness rgdd          ${witnesses.rgdd}
        witness smartit       ${witnesses.smartit}

        witness glasklar      ${witnesses.glasklar}
        witness mullvad       ${witnesses.mullvad}

        group test-2of3 2 nisse rgdd smartit
        group prod-all all glasklar mullvad
        group combined any test-2of3 prod-all

        # Final quorum
        quorum combined`;

    const policy = await parsePolicyText(text);

    expect(policy.logs.size).toBe(2);
    expect(policy.witnesses.size).toBe(5);
    expect(policy.quorum).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const quorum = policy.quorum as any;
    expect(quorum.k).toBe(1);
    expect(quorum.subQuorums.length).toBe(2);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const subKs = quorum.subQuorums.map((q: any) => q.k).sort();
    expect(subKs).toEqual([2, 2]);
  });

  it("fails on unknown keyword", async () => {
    const text = `
      log ${log1}
      witness nisse ${witnesses.nisse}
      invalid_keyword something
      quorum none
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "Unknown keyword: invalid_keyword",
    );
  });

  it("fails if nested group name is undefined", async () => {
    const text = `
      log ${log1}
      witness nisse ${witnesses.nisse}
      group outer 1 nested
      quorum outer
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "undefined name: nested",
    );
  });

  it("fails if group threshold is impossible (5 of 4)", async () => {
    const text = `
      log ${log1}
      witness n1 ${witnesses.nisse}
      witness n2 ${witnesses.rgdd}
      witness n3 ${witnesses.smartit}
      witness n4 ${witnesses.glasklar}
      group impossible 5 n1 n2 n3 n4
      quorum impossible
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "invalid threshold",
    );
  });

  it("fails on invalid syntax (missing witness name)", async () => {
    const text = `
      log ${log1}
      witness ${witnesses.nisse}
      quorum none
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "witness line must include name and pubkey and optional URL",
    );
  });

  it("fails on invalid key length", async () => {
    const text = `
      log ${log1}
      witness nisse 123abc
      quorum none
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "Ed25519 raw keys must be exactly 32-bytes",
    );
  });

  it("fails on duplicated log key", async () => {
    const text = `
      log ${log2}
      log ${log2}
      witness nisse ${witnesses.nisse}
      quorum nisse
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      /Duplicate log key:/,
    );
  });

  it("fails on duplicated witness key", async () => {
    const text = `
      log ${log1}
      log ${log2}
      witness nisse ${witnesses.nisse}
      witness duplicated ${witnesses.nisse}
      quorum nisse
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      /Duplicate witness key:/,
    );
  });

  it("fails on duplicated witness key", async () => {
    const text = `
      log ${log1}
      log ${log2}
      witness nisse ${witnesses.nisse}
      witness nisse ${witnesses.rgdd}
      quorum nisse
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "duplicate name: nisse",
    );
  });

  it("fails on too many arguments", async () => {
    const text = `
      log ${log1} https://url extra-argument
      log ${log2}
      witness nisse ${witnesses.nisse}
      quorum nisse
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "log line must include pubkey and optional URL",
    );
  });

  it("fails on group with less than 3 arguments", async () => {
    const text = `
      log ${log1}
      log ${log2}
      witness nisse ${witnesses.nisse}
      witness rgdd ${witnesses.rgdd}
      group broken-group 1
      quorum broken-group
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "group requires name, threshold, and members",
    );
  });

  it("fails on duplicate group name", async () => {
    const text = `
      log ${log1}
      log ${log2}
      witness nisse ${witnesses.nisse}
      witness rgdd ${witnesses.rgdd}
      group duplicate-group 1 nisse
      group duplicate-group 1 rgdd
      quorum broken-group
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "duplicate group name: duplicate-group",
    );
  });

  it("fails when a witness is listed twice in a group", async () => {
    const text = `
      log ${log1}
      witness nisse ${witnesses.nisse}
      group duplicated 2 nisse nisse
      quorum duplicated
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "nisse is already a member of duplicated",
    );
  });

  it("fails when a witness is reused across groups", async () => {
    const text = `
      log ${log1}
      witness nisse ${witnesses.nisse}
      group first any nisse
      group second any nisse
      quorum second
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "nisse is already a member of first",
    );
  });

  it("fails when none is used as a group member", async () => {
    const text = `
      log ${log1}
      group invalid any none
      quorum invalid
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "none cannot be a group member",
    );
  });

  it("fails without a quorum", async () => {
    const text = `
      log ${log1}
      witness nisse ${witnesses.nisse}
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "no quorum defined",
    );
  });

  it("fails on duplicate quorum keyword", async () => {
    const text = `
      log ${log1}
      log ${log2}
      witness nisse ${witnesses.nisse}
      witness rgdd ${witnesses.rgdd}
      group a-group 1 nisse
      group b-group 1 rgdd
      quorum a-group
      quorum b-group
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "quorum can only be set once",
    );
  });

  it("fails on quorum with non-existant group", async () => {
    const text = `
      log ${log1}
      log ${log2}
      witness nisse ${witnesses.nisse}
      witness rgdd ${witnesses.rgdd}
      group a-group 1 nisse
      group b-group 1 rgdd
      quorum c-group
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "undefined name: c-group",
    );
  });

  it("fails on malformed quorum line", async () => {
    const text = `
      log ${log1}
      log ${log2}
      witness nisse ${witnesses.nisse}
      quorum nisse 2
    `;
    await expect(() => parsePolicyText(text)).rejects.toThrow(
      "quorum requires a single name",
    );
  });
});
