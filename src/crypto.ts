import { prefixInteriorNode } from "./constants";
import { stringToUint8Array } from "./encoding";
import { formatCheckpoint, formatCosignedData } from "./format";
import {
  Cosignature,
  Hash,
  KeyHash,
  PublicKey,
  RawPublicKey,
  Signature,
  SignedTreeHead,
  TreeHead,
} from "./types";

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

export function constantTimeBufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

export async function importKey(
  rawPublicKey: RawPublicKey,
): Promise<PublicKey> {
  if (rawPublicKey.bytes.length !== 32) {
    throw new Error("Ed25519 raw keys must be exactly 32-bytes");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(rawPublicKey.bytes),
    "Ed25519",
    true,
    ["verify"],
  );

  return new PublicKey(key);
}

export async function verifySignature(
  key: PublicKey,
  signature: Signature,
  message: Uint8Array,
): Promise<boolean> {
  if (signature.bytes.length !== 64) {
    throw new Error("Signature must be 64 bytes for Ed25519.");
  }

  return await crypto.subtle.verify(
    { name: "Ed25519" },
    key.key,
    toArrayBuffer(signature.bytes),
    toArrayBuffer(message),
  );
}

export async function hashKey(publicKey: PublicKey): Promise<KeyHash> {
  const rawBuffer = await crypto.subtle.exportKey("raw", publicKey.key);
  const raw = new RawPublicKey(rawBuffer);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    raw.bytes.buffer as ArrayBuffer,
  );
  return new KeyHash(digest);
}

export async function hashMessage(message: Uint8Array): Promise<Hash> {
  return new Hash(await crypto.subtle.digest("SHA-256", toArrayBuffer(message)));
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
  const prefix = prefixInteriorNode;
  const combined = new Uint8Array(1 + left.bytes.length + right.bytes.length);
  combined.set(prefix, 0);
  combined.set(left.bytes, 1);
  combined.set(right.bytes, 1 + left.bytes.length);

  const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
  const hash = new Hash(hashBuffer);

  return hash;
}

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
    if (!constantTimeBufferEqual(leafHash.bytes, treeHead.RootHash.bytes)) {
      throw new Error("tree size is 1 but leaf does not match the root");
    }
    return true;
  }

  let currentHash = leafHash;
  let currentIndex = leafIndex;
  let lastNodeIndex = treeHead.Size - 1;
  let pathIndex = 0;
  const nextSibling = (): Hash => {
    const sibling = path[pathIndex++];
    if (!sibling) throw new Error("proof input is malformed: path too short");
    return sibling;
  };

  while (lastNodeIndex > 0) {
    if (currentIndex % 2 === 1) {
      currentHash = await hashInteriorNode(nextSibling(), currentHash);
    } else if (currentIndex < lastNodeIndex) {
      currentHash = await hashInteriorNode(currentHash, nextSibling());
    }

    currentIndex = Math.floor(currentIndex / 2);
    lastNodeIndex = Math.floor(lastNodeIndex / 2);
  }

  if (pathIndex !== path.length) {
    throw new Error("internal error: unused path elements");
  }

  if (!constantTimeBufferEqual(currentHash.bytes, treeHead.RootHash.bytes)) {
    throw new Error("invalid proof: root hash does not match computed value");
  }

  return true;
}
