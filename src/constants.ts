import { stringToUint8Array } from "./encoding.js";

export const CheckpointNamePrefix = "sigsum.org/v1/tree/";
export const CosignatureNamespace = "cosignature/v1";
export const LeafNamespace = stringToUint8Array("sigsum.org/v1/tree-leaf");
export const prefixLeafNode = new Uint8Array([0]);
export const prefixInteriorNode = new Uint8Array([1]);
