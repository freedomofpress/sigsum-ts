// https://git.glasklar.is/nisse/sigsum-c/-/blob/main/tools/sigsum-compile-policy.c?ref_type=heads

import { parsePolicyText } from "./config";
import { base64ToUint8Array } from "./encoding";
import { Entity, isQuorumKofN, isQuorumSingle, Policy, Quorum } from "./policy";
import { Base64KeyHash, KeyHash, RawPublicKey } from "./types";

const BYTECODE_ADD = 0x01;

interface WitnessNode {
  kind: "witness";
  bytecodeSize: number;
  witnessIndex: number;
}

interface GroupNode {
  kind: "group";
  bytecodeSize: number;
  threshold: number;
  members: PreparedNode[];
}

type PreparedNode = WitnessNode | GroupNode;

interface KeyEntry {
  encoded: Base64KeyHash;
  hash: KeyHash;
  raw: RawPublicKey;
}

const compareUint8Arrays = (a: Uint8Array, b: Uint8Array): number => {
  for (let i = 0, n = Math.min(a.length, b.length); i < n; i++)
    if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

async function exportRawKey(entity: Entity): Promise<RawPublicKey> {
  return new RawPublicKey(
    await crypto.subtle.exportKey("raw", entity.publicKey.key),
  );
}

async function collectSortedEntries(
  map: Map<Base64KeyHash, Entity>,
): Promise<KeyEntry[]> {
  const entries: KeyEntry[] = [];

  for (const [encoded, entity] of map.entries()) {
    const raw = await exportRawKey(entity);
    const hash = new KeyHash(base64ToUint8Array(encoded.value));

    entries.push({
      encoded, // Base64KeyHash
      hash, // KeyHash
      raw, // RawPublicKey
    });
  }

  entries.sort((a, b) => compareUint8Arrays(a.hash.bytes, b.hash.bytes));

  return entries;
}

function bytecodeSizeWithPrefix(value: number): number {
  let size = 1;
  for (value >>= 6; value > 0; value >>= 6) size++;
  return size;
}

function bytecodeWritePrefix(
  bytecode: Uint8Array,
  offset: number,
  size: number,
  prefix: number,
): void {
  while (size-- > 0) {
    const shift = size * 6;
    bytecode[offset++] = 0xc0 | ((prefix >> shift) & 0x3f);
  }
}

function bytecodeWriteWitness(
  bytecode: Uint8Array,
  offset: number,
  size: number,
  witness: number,
): void {
  if (size <= 0) throw new Error("invalid witness encoding length");
  if (size > 1) bytecodeWritePrefix(bytecode, offset, size - 1, witness >> 6);
  bytecode[offset + size - 1] = 0x40 | (witness & 0x3f);
}

function bytecodeWriteThreshold(
  bytecode: Uint8Array,
  offset: number,
  size: number,
  threshold: number,
): void {
  if (size <= 0) throw new Error("invalid threshold encoding length");
  if (size > 1) bytecodeWritePrefix(bytecode, offset, size - 1, threshold >> 6);
  bytecode[offset + size - 1] = 0x80 | (threshold & 0x3f);
}

function groupBytecodeSort(
  bytecode: Uint8Array,
  offset: number,
  first: boolean,
  interval: number,
  size: number,
): number {
  if (interval > 1) {
    const blocks: Uint8Array[] = [];
    for (let i = 0; i < interval; i++) {
      const start = offset + i * size;
      blocks.push(bytecode.slice(start, start + size));
    }
    blocks.sort(compareUint8Arrays);
    for (let i = 0; i < interval; i++) {
      bytecode.set(blocks[i], offset + i * size);
    }
  }

  if (first) {
    interval--;
    if (interval === 0) return size;
    offset += size;
  }

  for (let i = interval; i > 1; ) {
    const addPos = offset + i * (size + 1) - 1;
    bytecode[addPos] = BYTECODE_ADD;
    i--;
    const srcStart = offset + i * size;
    const destStart = offset + i * (size + 1);
    bytecode.copyWithin(destStart, srcStart, srcStart + size);
  }
  bytecode[offset + size] = BYTECODE_ADD;
  return (interval + (first ? 1 : 0)) * size + interval;
}

function prepareQuorum(
  quorum: Quorum,
  witnessIndex: Map<Base64KeyHash, number>,
): PreparedNode {
  if (isQuorumSingle(quorum)) {
    const index = witnessIndex.get(quorum.witness);
    if (index === undefined)
      throw new Error("witness referenced in quorum but missing from policy");
    return {
      kind: "witness",
      witnessIndex: index,
      bytecodeSize: bytecodeSizeWithPrefix(index),
    };
  }
  if (!isQuorumKofN(quorum)) throw new Error("unsupported quorum type");

  const members = quorum.members.map((member) =>
    prepareQuorum(member, witnessIndex),
  );
  if (members.length === 0) {
    if (quorum.threshold !== 0) throw new Error("empty quorum group");
    return { kind: "group", members, threshold: 0, bytecodeSize: 0 };
  }

  if (members.length === 1) {
    return {
      kind: "group",
      members,
      threshold: quorum.threshold,
      bytecodeSize: members[0].bytecodeSize,
    };
  }

  members.sort((a, b) => a.bytecodeSize - b.bytecodeSize);

  const bytecodeSize =
    members.reduce((acc, member) => acc + member.bytecodeSize, 0) +
    (members.length - 1) +
    bytecodeSizeWithPrefix(quorum.threshold);

  return {
    kind: "group",
    members,
    threshold: quorum.threshold,
    bytecodeSize,
  };
}

function compileQuorum(
  node: PreparedNode,
  bytecode: Uint8Array,
  offset: number,
): number {
  if (node.kind === "witness") {
    bytecodeWriteWitness(
      bytecode,
      offset,
      node.bytecodeSize,
      node.witnessIndex,
    );
    return node.bytecodeSize;
  }

  const members = node.members;
  if (members.length === 0) return 0;
  const first = members[0];
  let left = node.bytecodeSize;
  let currentSize = first.bytecodeSize;
  left -= currentSize;
  let blockOffset = offset;
  compileQuorum(first, bytecode, blockOffset);

  if (members.length === 1) {
    return node.bytecodeSize;
  }

  let startMember = 0;

  for (let i = 1; i < members.length; i++) {
    const member = members[i];
    if (member.bytecodeSize > currentSize) {
      const interval = i - startMember;
      const nadd = interval - (startMember === 0 ? 1 : 0);
      left -= nadd;
      const consumed = groupBytecodeSort(
        bytecode,
        blockOffset,
        startMember === 0,
        interval,
        currentSize,
      );
      blockOffset += consumed;
      startMember = i;
      currentSize = member.bytecodeSize;
    }
    left -= member.bytecodeSize;
    const target = blockOffset + (i - startMember) * currentSize;
    compileQuorum(member, bytecode, target);
  }

  const interval = members.length - startMember;
  const nadd = interval - (startMember === 0 ? 1 : 0);
  const consumed = groupBytecodeSort(
    bytecode,
    blockOffset,
    startMember === 0,
    interval,
    currentSize,
  );
  blockOffset += consumed;
  const thresholdSize = left - nadd;
  bytecodeWriteThreshold(bytecode, blockOffset, thresholdSize, node.threshold);
  return node.bytecodeSize;
}

export async function compilePolicy(policyText: string): Promise<Uint8Array> {
  const policy = await parsePolicyText(policyText);
  return compilePolicyFromParsed(policy);
}

export async function compilePolicyFromParsed(
  policy: Policy,
): Promise<Uint8Array> {
  const logEntries = await collectSortedEntries(policy.logs);
  const witnessEntries = await collectSortedEntries(policy.witnesses);

  if (logEntries.length > 0xff)
    throw new Error(
      `Policy lists ${logEntries.length} logs, can have at most 255.`,
    );
  if (witnessEntries.length > 0xff)
    throw new Error(
      `Policy lists ${witnessEntries.length} witnesses, can have at most 255.`,
    );

  const witnessIndex = new Map<Base64KeyHash, number>();
  witnessEntries.forEach((entry, index) => {
    witnessIndex.set(entry.encoded, index);
  });

  const prepared = prepareQuorum(policy.quorum, witnessIndex);
  if (prepared.bytecodeSize > 0xff)
    throw new Error(
      `Policy quorum too complex, ${prepared.bytecodeSize} instructions, can have at most 255.`,
    );

  const quorumBytecode = new Uint8Array(prepared.bytecodeSize);
  compileQuorum(prepared, quorumBytecode, 0);

  const totalSize =
    4 +
    logEntries.reduce((acc, entry) => acc + entry.raw.bytes.length, 0) +
    witnessEntries.reduce((acc, entry) => acc + entry.raw.bytes.length, 0) +
    quorumBytecode.length;

  const output = new Uint8Array(totalSize);
  output[0] = 0;
  output[1] = logEntries.length;
  output[2] = witnessEntries.length;
  output[3] = quorumBytecode.length;

  let offset = 4;
  for (const entry of logEntries) {
    output.set(entry.raw.bytes, offset);
    offset += entry.raw.bytes.length;
  }
  for (const entry of witnessEntries) {
    output.set(entry.raw.bytes, offset);
    offset += entry.raw.bytes.length;
  }

  output.set(quorumBytecode, offset);

  return output;
}
