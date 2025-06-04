import { CheckpointNamePrefix, CosignatureNamespace } from "./constants";
import { Uint8ArrayToBase64, Uint8ArrayToHex } from "./encoding";
import { KeyHash, TreeHead } from "./types";

export function formatCheckpoint(
  treeHead: TreeHead,
  logKeyHash: KeyHash,
): string {
  const origin = CheckpointNamePrefix + Uint8ArrayToHex(logKeyHash);
  const rootHash = Uint8ArrayToBase64(treeHead.RootHash);
  const checkpointStr = `${origin}\n${treeHead.Size}\n${rootHash}\n`;
  return checkpointStr;
}

export function formatCosignedData(
  treeHead: TreeHead,
  logKeyHash: KeyHash,
  timestamp: number,
): string {
  const checkpointStr = formatCheckpoint(treeHead, logKeyHash);
  const cosignedStr = `${CosignatureNamespace}\ntime ${timestamp}\n${checkpointStr}`;
  return cosignedStr;
}

export function attachNamespace(
  namespace: Uint8Array,
  hash: Uint8Array,
): Uint8Array {
  const result = new Uint8Array(namespace.length + 1 + hash.length);
  result.set(namespace, 0);
  result[namespace.length] = 0;
  result.set(hash, namespace.length + 1);
  return result;
}
