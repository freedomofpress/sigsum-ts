import {
  evalQuorumBytecode,
  importAndHashAll,
  parseCompiledPolicy,
} from "./compiledPolicy";
import { parsePolicyText } from "./config";
import { LeafNamespace } from "./constants";
import {
  constantTimeBufferEqual,
  hashKey,
  hashMessage,
  importKey,
  verifyCosignedTreeHead,
  verifyInclusionProof,
  verifySignature,
  verifySignedTreeHead,
} from "./crypto";
import { Uint8ArrayToBase64 } from "./encoding";
import { attachNamespace } from "./format";
import { Policy } from "./policy";
import { SigsumProof } from "./proof";
import { Base64KeyHash, Hash, PublicKey, RawPublicKey } from "./types";

async function verifyCommon(
  message_hash: Uint8Array,
  submitterRawPublicKey: RawPublicKey,
  proof: SigsumProof,
  getLogKey: () => Promise<PublicKey>,
  evalQuorum: () => Promise<boolean>,
): Promise<boolean> {
  if (message_hash.length !== 32) {
    throw new Error("message hash must be exactly 32 bytes");
  }
  const submitterPublicKey = await importKey(submitterRawPublicKey);
  const submitterKeyHash = await hashKey(submitterPublicKey);

  // Step 1 — double hash (leaf data, then checksum)
  const checksum: Hash = await hashMessage(message_hash);

  // Step 2 — leaf key must match submitter key
  if (
    !constantTimeBufferEqual(proof.leaf.KeyHash.bytes, submitterKeyHash.bytes)
  ) {
    throw new Error("proof key does not match the provided one");
  }

  // Step 3 — verify leaf signature
  if (
    !(await verifySignature(
      submitterPublicKey,
      proof.leaf.Signature,
      attachNamespace(LeafNamespace, checksum.bytes),
    ))
  ) {
    throw new Error("invalid message signature");
  }

  // Step 4 — log signature
  const logPub = await getLogKey();
  if (
    !(await verifySignedTreeHead(
      proof.treeHead.SignedTreeHead,
      logPub,
      proof.logKeyHash,
    ))
  ) {
    throw new Error("failed to verify tree head signature");
  }

  // Step 5 — quorum evaluation (different per policy type)
  if (!(await evalQuorum())) {
    throw new Error("cosignature quorum not satisfied");
  }

  // Step 6 — inclusion proof
  return await verifyInclusionProof(
    await proof.leaf.toLeaf(checksum).hashLeaf(),
    proof.inclusion.LeafIndex,
    proof.treeHead.SignedTreeHead.TreeHead,
    proof.inclusion.Path,
  );
}

export async function verifyHash(
  message_hash: Uint8Array,
  submitterRawPublicKey: RawPublicKey,
  policyText: string,
  proofText: string,
): Promise<boolean> {
  const policy: Policy = await parsePolicyText(policyText);
  const proof: SigsumProof = await SigsumProof.fromAscii(proofText);

  async function getLogKey(): Promise<PublicKey> {
    const keyHashB64 = new Base64KeyHash(
      Uint8ArrayToBase64(proof.logKeyHash.bytes),
    );
    const log = Base64KeyHash.lookup(policy.logs, keyHashB64);
    if (!log) throw new Error("log key not found in policy");
    return log.publicKey;
  }

  async function evalQuorum(): Promise<boolean> {
    const present = new Set<Base64KeyHash>();
    for (const [keyHash, entity] of policy.witnesses) {
      const cosig = Base64KeyHash.lookup(proof.treeHead.Cosignatures, keyHash);
      if (!cosig) continue;
      if (
        await verifyCosignedTreeHead(
          proof.treeHead.SignedTreeHead.TreeHead,
          entity.publicKey,
          proof.logKeyHash,
          cosig,
        )
      ) {
        present.add(keyHash);
        if (policy.quorum.isQuorum(present)) return true;
      }
    }
    return false;
  }

  return verifyCommon(
    message_hash,
    submitterRawPublicKey,
    proof,
    getLogKey,
    evalQuorum,
  );
}

export async function verifyHashWithCompiledPolicy(
  message_hash: Uint8Array,
  submitterRawPublicKey: RawPublicKey,
  compiledPolicy: Uint8Array,
  proofText: string,
): Promise<boolean> {
  const proof = await SigsumProof.fromAscii(proofText);
  const compiled = parseCompiledPolicy(compiledPolicy);

  const logs = await importAndHashAll(compiled.logsRaw);
  const witnesses = await importAndHashAll(compiled.witnessesRaw);

  async function getLogKey(): Promise<PublicKey> {
    const log = new Base64KeyHash(Uint8ArrayToBase64(proof.logKeyHash.bytes));

    for (const { b64, pub } of logs) {
      if (b64.equals(log)) {
        return pub;
      }
    }

    throw new Error("log key not found in compiled policy");
  }

  async function evalQuorum(): Promise<boolean> {
    const present = new Uint8Array(witnesses.length);
    for (const [i, w] of witnesses.entries()) {
      const cosig = Base64KeyHash.lookup(proof.treeHead.Cosignatures, w.b64);
      if (!cosig) continue;

      if (
        await verifyCosignedTreeHead(
          proof.treeHead.SignedTreeHead.TreeHead,
          w.pub,
          proof.logKeyHash,
          cosig,
        )
      ) {
        present[i] = 1;
      }
    }
    return evalQuorumBytecode(compiled.quorum, witnesses.length, present);
  }

  return verifyCommon(
    message_hash,
    submitterRawPublicKey,
    proof,
    getLogKey,
    evalQuorum,
  );
}

export async function verifyMessage(
  message: Uint8Array,
  submitterRawPublicKey: RawPublicKey,
  policyText: string,
  proofText: string,
): Promise<boolean> {
  return verifyHash(
    (await hashMessage(message)).bytes,
    submitterRawPublicKey,
    policyText,
    proofText,
  );
}

export async function verifyMessageWithCompiledPolicy(
  message: Uint8Array,
  submitterRawPublicKey: RawPublicKey,
  compiledPolicy: Uint8Array,
  proofText: string,
): Promise<boolean> {
  return verifyHashWithCompiledPolicy(
    (await hashMessage(message)).bytes,
    submitterRawPublicKey,
    compiledPolicy,
    proofText,
  );
}
