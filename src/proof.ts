import { hexToUint8Array, Uint8ArrayToBase64 } from "./encoding";
import {
  Base64KeyHash,
  Cosignature,
  CosignedTreeHead,
  Hash,
  InclusionProof,
  KeyHash,
  ShortLeaf,
  Signature,
} from "./types";

const HASH_BYTES = 32;
const SIGNATURE_BYTES = 64;
const MAX_INCLUSION_PATH = 63;

function valueFor(line: string | undefined, key: string): string | null {
  const prefix = `${key}=`;
  return line?.startsWith(prefix) ? line.slice(prefix.length) : null;
}

function parseUint(value: string, name: string, allowZero = true): number {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`invalid ${name}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || (!allowZero && parsed === 0)) {
    throw new Error(`invalid ${name}`);
  }
  return parsed;
}

function parseHex(value: string, length: number, name: string): Uint8Array {
  const bytes = hexToUint8Array(value);
  if (bytes.length !== length) throw new Error(`${name} must be ${length} bytes`);
  return bytes;
}

export function parseCosignedTreeHead(lines: string[]): CosignedTreeHead {
  const sizeValue =
    valueFor(lines[0], "tree_size") ?? valueFor(lines[0], "size");
  if (sizeValue === null) throw new Error("missing tree head start");
  const size = parseUint(sizeValue, "tree size", false);

  const rootValue = valueFor(lines[1], "root_hash");
  if (rootValue === null) throw new Error("missing tree_head fields");
  const rootHash = new Hash(parseHex(rootValue, HASH_BYTES, "root_hash"));

  const signatureValue = valueFor(lines[2], "signature");
  if (signatureValue === null) throw new Error("missing tree head signature");
  const signature = new Signature(
    parseHex(signatureValue, SIGNATURE_BYTES, "signature"),
  );

  const cosignatures = new Map<Base64KeyHash, Cosignature>();
  const seen = new Set<string>();
  for (const line of lines.slice(3)) {
    const value = valueFor(line, "cosignature");
    if (value === null) throw new Error(`invalid tree head line: ${line}`);

    const parts = value.split(" ");
    if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
      throw new Error("invalid cosignature format");
    }

    const keyHash = new Base64KeyHash(
      Uint8ArrayToBase64(
        parseHex(parts[0], HASH_BYTES, "cosignature key hash"),
      ),
    );
    if (seen.has(keyHash.value)) throw new Error("duplicate cosignature");
    seen.add(keyHash.value);

    cosignatures.set(keyHash, {
      Timestamp: parseUint(parts[1], "cosignature timestamp"),
      Signature: new Signature(
        parseHex(parts[2], SIGNATURE_BYTES, "cosignature signature"),
      ),
    });
  }

  return {
    SignedTreeHead: {
      TreeHead: { Size: size, RootHash: rootHash },
      Signature: signature,
    },
    Cosignatures: cosignatures,
  };
}

export function parseInclusionProof(lines: string[]): InclusionProof {
  const indexValue = valueFor(lines[0], "leaf_index");
  if (indexValue === null) {
    if (lines[0]?.startsWith("leaf_index")) {
      throw new Error("invalid line in inclusion proof: leaf_index");
    }
    throw new Error("missing leaf_index line in inclusion proof");
  }
  if (indexValue.length === 0) {
    throw new Error("invalid line in inclusion proof: leaf_index");
  }

  const path: Hash[] = [];
  for (const line of lines.slice(1)) {
    if (line.startsWith("leaf_index=")) {
      throw new Error("duplicate leaf_index line in inclusion proof");
    }
    const value = valueFor(line, "node_hash");
    if (value === null) {
      throw new Error(`invalid line in inclusion proof: ${line}`);
    }
    path.push(new Hash(parseHex(value, HASH_BYTES, "node_hash")));
    if (path.length > MAX_INCLUSION_PATH) {
      throw new Error("inclusion proof path is too long");
    }
  }

  return {
    LeafIndex: parseUint(indexValue, "leaf_index value"),
    Path: path,
  };
}

export class SigsumProof {
  version: number;
  logKeyHash: KeyHash;
  leaf: ShortLeaf;
  treeHead: CosignedTreeHead;
  inclusion: InclusionProof;

  constructor(
    version: number,
    logKeyHash: KeyHash,
    leaf: ShortLeaf,
    treeHead: CosignedTreeHead,
    inclusion: InclusionProof,
  ) {
    this.version = version;
    this.logKeyHash = logKeyHash;
    this.leaf = leaf;
    this.treeHead = treeHead;
    this.inclusion = inclusion;
  }

  static async fromAscii(text: string): Promise<SigsumProof> {
    const lines = text.trim().split(/\r?\n/);

    const versionValue = valueFor(lines[0], "version");
    if (versionValue === null) throw new Error("missing version line");
    const version = parseUint(versionValue, "proof version");
    if (version !== 1 && version !== 2) {
      throw new Error(`unknown proof version ${version}`);
    }

    const logValue = valueFor(lines[1], "log");
    if (logValue === null) throw new Error("missing log line");
    const logKeyHash = new KeyHash(parseHex(logValue, HASH_BYTES, "log"));

    const leafValue = valueFor(lines[2], "leaf");
    if (leafValue === null) throw new Error("missing leaf line");
    const leafParts = leafValue.split(" ");
    if (leafParts.length !== (version === 1 ? 3 : 2)) {
      throw new Error("invalid leaf line format");
    }
    if (version === 1) parseHex(leafParts[0], 2, "leaf checksum");
    const offset = version === 1 ? 1 : 0;
    const leaf = new ShortLeaf(
      new KeyHash(parseHex(leafParts[offset], HASH_BYTES, "leaf key hash")),
      new Signature(
        parseHex(leafParts[offset + 1], SIGNATURE_BYTES, "leaf signature"),
      ),
    );

    if (lines[3] !== "") throw new Error("missing leaf separator");
    const treeStart = 4;
    const inclusionStart = lines.indexOf("", treeStart);
    const treeLines = lines.slice(
      treeStart,
      inclusionStart === -1 ? lines.length : inclusionStart,
    );
    const treeHead = parseCosignedTreeHead(treeLines);

    if (inclusionStart === -1) {
      throw new Error("missing leaf_index line in inclusion proof");
    }
    const inclusion = parseInclusionProof(lines.slice(inclusionStart + 1));

    return new SigsumProof(version, logKeyHash, leaf, treeHead, inclusion);
  }
}
