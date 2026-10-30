import {
  getSubtle,
  hashChildren,
  importKey as importRawKey,
  sha256,
  stringToUint8Array,
  uint8ArrayEqual,
  Uint8ArrayToHex,
  verifyInclusionProof as verifyInclusionProofBytes,
  verifySignature as verifyBytes,
} from "@freedomofpress/crypto-browser";

import { formatCheckpoint, formatCosignedData } from "./format.js";
import {
  Cosignature,
  Hash,
  KeyHash,
  PublicKey,
  RawPublicKey,
  Signature,
  SignedTreeHead,
  TreeHead,
} from "./types.js";

export { uint8ArrayEqual as constantTimeBufferEqual };

export async function importKey(
  rawPublicKey: RawPublicKey,
): Promise<PublicKey> {
  if (rawPublicKey.bytes.length !== 32) {
    throw new Error("Ed25519 raw keys must be exactly 32-bytes");
  }
  return new PublicKey(
    await importRawKey(
      "ed25519",
      "ed25519",
      Uint8ArrayToHex(rawPublicKey.bytes),
    ),
  );
}

export async function verifySignature(
  key: PublicKey,
  signature: Signature,
  message: Uint8Array,
): Promise<boolean> {
  if (signature.bytes.length !== 64) {
    throw new Error("Signature must be 64 bytes for Ed25519.");
  }

  return verifyBytes(key.key, message, signature.bytes);
}

export async function exportRawKey(key: CryptoKey): Promise<RawPublicKey> {
  const subtle = await getSubtle();
  return new RawPublicKey(await subtle.exportKey("raw", key));
}

export async function hashKey(publicKey: PublicKey): Promise<KeyHash> {
  return new KeyHash(await sha256((await exportRawKey(publicKey.key)).bytes));
}

export async function hashMessage(message: Uint8Array): Promise<Hash> {
  return new Hash(await sha256(message));
}

export async function verifySignedTreeHead(
  signedTreeHead: SignedTreeHead,
  publicKey: PublicKey,
  logKeyHash: KeyHash,
): Promise<boolean> {
  const checkpoint = formatCheckpoint(signedTreeHead.TreeHead, logKeyHash);
  return await verifySignature(
    publicKey,
    signedTreeHead.Signature,
    stringToUint8Array(checkpoint),
  );
}

export async function verifyCosignedTreeHead(
  treeHead: TreeHead,
  witnessPublicKey: PublicKey,
  logKeyHash: KeyHash,
  cosignature: Cosignature,
): Promise<boolean> {
  const cosignedCheckpoint = formatCosignedData(
    treeHead,
    logKeyHash,
    cosignature.Timestamp,
  );

  return await verifySignature(
    witnessPublicKey,
    cosignature.Signature,
    stringToUint8Array(cosignedCheckpoint),
  );
}

export async function hashInteriorNode(left: Hash, right: Hash): Promise<Hash> {
  return new Hash(await hashChildren(left.bytes, right.bytes));
}

const bitLength = (n: bigint): number => (n === 0n ? 0 : n.toString(2).length);
const popCount = (n: bigint): number => n.toString(2).split("1").length - 1;

export async function verifyInclusionProof(
  leafHash: Hash,
  leafIndex: number,
  treeHead: TreeHead,
  path: Hash[],
): Promise<boolean> {
  if (
    !Number.isSafeInteger(leafIndex) ||
    !Number.isSafeInteger(treeHead.Size) ||
    leafIndex < 0 ||
    treeHead.Size < 1 ||
    leafIndex >= treeHead.Size
  ) {
    throw new Error("proof input is malformed: index out of range");
  }
  if (
    leafHash.bytes.length !== 32 ||
    treeHead.RootHash.bytes.length !== 32 ||
    path.length > 63 ||
    path.some((hash) => hash.bytes.length !== 32)
  ) {
    throw new Error("proof input is malformed: invalid hash path");
  }

  if (treeHead.Size === 1) {
    if (path.length !== 0) {
      throw new Error("internal error: unused path elements");
    }
    if (!uint8ArrayEqual(leafHash.bytes, treeHead.RootHash.bytes)) {
      throw new Error("tree size is 1 but leaf does not match the root");
    }
    return true;
  }

  // RFC 9162 §2.1.3.2: one sibling per level up to where the paths to the
  // leaf and to the last leaf diverge, then one per set bit above it.
  const inner = bitLength(BigInt(leafIndex) ^ BigInt(treeHead.Size - 1));
  const expected = inner + popCount(BigInt(leafIndex) >> BigInt(inner));
  if (path.length > expected) {
    throw new Error("internal error: unused path elements");
  }
  if (path.length < expected) {
    throw new Error("proof input is malformed: path too short");
  }

  const ok = await verifyInclusionProofBytes(
    leafHash.bytes,
    leafIndex,
    treeHead.Size,
    treeHead.RootHash.bytes,
    path.map((hash) => hash.bytes),
  );
  if (!ok) {
    throw new Error("invalid proof: root hash does not match computed value");
  }

  return true;
}
