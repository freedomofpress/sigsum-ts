import { stringToUint8Array } from "@freedomofpress/crypto-browser";

export const CheckpointNamePrefix = "sigsum.org/v1/tree/";
export const CosignatureNamespace = "cosignature/v1";
export const LeafNamespace = stringToUint8Array("sigsum.org/v1/tree-leaf");
export const prefixLeafNode = new Uint8Array([0]);
