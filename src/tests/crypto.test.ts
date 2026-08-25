import { describe, expect, it } from "vitest";

import {
  constantTimeBufferEqual,
  hashInteriorNode,
  hashKey,
  hashMessage,
  importKey,
  verifyCosignedTreeHead,
  verifyInclusionProof,
  verifySignature,
  verifySignedTreeHead,
} from "../crypto";
import { Uint8ArrayToBase64 } from "../encoding";
import { SigsumProof } from "../proof";
import {
  Cosignature,
  Hash,
  KeyHash,
  RawPublicKey,
  Signature,
  SignedTreeHead,
  TreeHead,
} from "../types";

const PROOF = `
version=1
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=f62f 00004cce3ad5f54dceb2e20788b72b1c91a8c3913e7866670f5752fe14009f4d 7fdadea21d3268bceb9c4959f25ed8d7a0be2e23637bbcf795b861498626928bcde9180591c5d3c1d6b15b0b6a36df329226d312cde0bb36331888194df1680a

size=1
root_hash=f24ca2b7b234c380438fbeb7e6a3e7481705adf22b8ecab47ca049b31b642bd8
signature=a3e28bf1b8e97664ba2505ed1f02373af70ad86f5a794b8ddf77c9dfc2cda3766479cc53906312dc705f5892472eb1b1a60843f1fd0e0ea3442b6df6a7f11805
cosignature=e923764535cac36836d1af682a2a3e5352e2636ec29c1d34c00160e1f4946d31 1749045854 eb9670fc459a8a3ca226cda1cdc37079018e7e2ae94db426da8e25e181ca29fd651e5ab6e12b3b080fd93cf41304d78669da499744f2c8db8adf25d9fa1ecb0e

leaf_index=0
`;

const VALID_PUBLIC_KEY = new RawPublicKey(
  new Uint8Array([
    235, 19, 108, 27, 6, 73, 64, 86, 192, 69, 29, 238, 123, 65, 67, 224, 101,
    29, 252, 40, 19, 100, 69, 16, 20, 107, 207, 165, 169, 155, 37, 250,
  ]),
);

const VALID_SIGNATURE = new Signature(
  new Uint8Array([
    140, 73, 191, 148, 174, 113, 109, 220, 188, 161, 249, 35, 177, 149, 245, 65,
    158, 51, 120, 251, 158, 34, 237, 205, 237, 88, 184, 141, 20, 128, 74, 71, 0,
    60, 226, 131, 180, 173, 121, 45, 248, 102, 92, 139, 157, 177, 87, 37, 78,
    237, 89, 63, 73, 23, 11, 132, 206, 122, 111, 0, 200, 140, 217, 4,
  ]),
);

const VALID_MESSAGE = new TextEncoder().encode("hello world");
const INVALID_MESSAGE = new TextEncoder().encode("tampered message");
const EXPECTED_BASE64_HASH = "fY20VJz2TPDYe09gUTGwfN6wiDFdSS9+O+5frwVd36c=";

const LOG_PUBKEY = new RawPublicKey(
  new Uint8Array([
    0x46, 0x44, 0xaf, 0x2a, 0xbd, 0x40, 0xf4, 0x89, 0x5a, 0x00, 0x3b, 0xca,
    0x35, 0x0f, 0x9d, 0x59, 0x12, 0xab, 0x30, 0x1a, 0x49, 0xc7, 0x7f, 0x13,
    0xe5, 0xb6, 0xd9, 0x05, 0xc2, 0x0a, 0x5f, 0xe6,
  ]),
);

const TREEHEAD_ROOT_HASH = new Hash(
  new Uint8Array([
    0x22, 0x59, 0x6c, 0x88, 0x2d, 0xcd, 0xfb, 0xfa, 0xba, 0x69, 0x3c, 0xb6,
    0x9b, 0x22, 0x5c, 0x81, 0xa8, 0xa9, 0x80, 0xe8, 0x4b, 0x3a, 0xd5, 0xfc,
    0x1f, 0xcd, 0x6a, 0x25, 0x6e, 0xbd, 0xc2, 0x35,
  ]),
);

const TREEHEAD_SIGNATURE = new Signature(
  new Uint8Array([
    0x3a, 0xec, 0xf6, 0x43, 0xc4, 0x2d, 0x15, 0x86, 0x30, 0x00, 0x57, 0x66,
    0x68, 0x98, 0x01, 0x07, 0xa0, 0x56, 0x98, 0x47, 0xf1, 0xb3, 0xf4, 0x3d,
    0xf7, 0x0d, 0xcb, 0xf0, 0x70, 0x5b, 0xb5, 0x80, 0xda, 0xf6, 0xfa, 0x64,
    0xc5, 0x86, 0xf4, 0xef, 0x78, 0x0a, 0x1b, 0x02, 0x08, 0x50, 0x30, 0xba,
    0xb9, 0x3c, 0x84, 0x51, 0x36, 0xed, 0x1f, 0x9c, 0x78, 0xec, 0x96, 0x13,
    0x93, 0xdf, 0xc1, 0x00,
  ]),
);

export const WITNESS_PUBKEY = new RawPublicKey(
  new Uint8Array([
    0x1c, 0x25, 0xf8, 0xa4, 0x4c, 0x63, 0x54, 0x57, 0xe2, 0xe3, 0x91, 0xd1,
    0xef, 0xbc, 0xa7, 0xd4, 0xc2, 0x95, 0x1a, 0x0a, 0xef, 0x06, 0x22, 0x5a,
    0x88, 0x1e, 0x46, 0xb9, 0x89, 0x62, 0xac, 0x6c,
  ]),
);

export const WITNESS_KEYHASH = new KeyHash(
  new Uint8Array([
    0x1c, 0x99, 0x72, 0x61, 0xf1, 0x6e, 0x6e, 0x81, 0xd1, 0x3f, 0x42, 0x09,
    0x00, 0xa2, 0x54, 0x2a, 0x4b, 0x6a, 0x04, 0x9c, 0x2d, 0x99, 0x63, 0x24,
    0xee, 0x5d, 0x82, 0xa9, 0x0c, 0xa3, 0x36, 0x0c,
  ]),
);

export const WITNESS_COSIGNATURE = new Signature(
  new Uint8Array([
    0x98, 0x2d, 0xfe, 0x23, 0xaf, 0x26, 0x4d, 0xe2, 0x76, 0xe3, 0x55, 0x67,
    0xe1, 0x62, 0x13, 0x9a, 0xd2, 0xcd, 0xba, 0xc9, 0x47, 0xb9, 0xff, 0x6d,
    0xc7, 0x0a, 0xee, 0x02, 0xc3, 0xaa, 0x79, 0x8b, 0x3a, 0x46, 0xdc, 0x7d,
    0x28, 0x90, 0x67, 0x10, 0x7e, 0x52, 0xd1, 0x0d, 0xa0, 0x57, 0x12, 0x92,
    0x38, 0xe0, 0x7a, 0xfc, 0x33, 0xa1, 0x61, 0x0a, 0x28, 0x33, 0xf5, 0xfc,
    0xc3, 0x33, 0x44, 0x01,
  ]),
);

export const WITNESS_TIMESTAMP = 1748943073;

describe("crypto", () => {
  it("imports a valid Ed25519 raw public key", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);

    expect(key.key.type).toBe("public");
    expect(key.key.algorithm.name).toBe("Ed25519");
    expect(key.key.extractable).toBe(true);
    expect(key.key.usages).toEqual(["verify"]);
  });

  it("imports a public key view", async () => {
    const backing = new Uint8Array(34);
    backing.set(VALID_PUBLIC_KEY.bytes, 1);
    const key = await importKey(new RawPublicKey(backing.subarray(1, 33)));
    expect(key.key.type).toBe("public");
  });

  it("throws on invalid raw public key length", async () => {
    const badKey = VALID_PUBLIC_KEY.bytes.slice(0, 30);
    await expect(importKey(new RawPublicKey(badKey))).rejects.toThrow();
  });

  it("returns true for a valid signature", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const ok = await verifySignature(key, VALID_SIGNATURE, VALID_MESSAGE);
    expect(ok).toBe(true);
  });

  it("verifies signature and message views", async () => {
    const message = new Uint8Array(VALID_MESSAGE.length + 2);
    const signature = new Uint8Array(VALID_SIGNATURE.bytes.length + 2);
    message.set(VALID_MESSAGE, 1);
    signature.set(VALID_SIGNATURE.bytes, 1);
    const key = await importKey(VALID_PUBLIC_KEY);
    const ok = await verifySignature(
      key,
      new Signature(signature.subarray(1, signature.length - 1)),
      message.subarray(1, message.length - 1),
    );
    expect(ok).toBe(true);
  });

  it("returns false if message is tampered", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const ok = await verifySignature(key, VALID_SIGNATURE, INVALID_MESSAGE);
    expect(ok).toBe(false);
  });

  it("throws if signature is too short", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    await expect(() =>
      verifySignature(key, new Signature(new Uint8Array(63)), VALID_MESSAGE),
    ).rejects.toThrow(/64 bytes/);
  });

  it("throws if signature is too long", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    await expect(() =>
      verifySignature(key, new Signature(new Uint8Array(65)), VALID_MESSAGE),
    ).rejects.toThrow(/64 bytes/);
  });

  it("returns false for all-zero public key", async () => {
    const zeroKey = await importKey(new RawPublicKey(new Uint8Array(32)));
    const ok = await verifySignature(zeroKey, VALID_SIGNATURE, VALID_MESSAGE);
    expect(ok).toBe(false);
  });

  it("returns false for all-0xFF public key", async () => {
    const ffKey = await importKey(
      new RawPublicKey(new Uint8Array(32).fill(0xff)),
    );
    const ok = await verifySignature(ffKey, VALID_SIGNATURE, VALID_MESSAGE);
    expect(ok).toBe(false);
  });

  it("returns a valid base64 SHA-256 hash", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const hash = Uint8ArrayToBase64((await hashKey(key)).bytes);
    expect(hash).toMatch(/^[a-zA-Z0-9+/]+={0,2}$/);
    expect(hash.length).toBeGreaterThan(40);
  });

  it("hashes only the bytes in a view", async () => {
    const backing = new Uint8Array([0, ...VALID_MESSAGE, 0]);
    const viewHash = await hashMessage(
      backing.subarray(1, backing.length - 1),
    );
    const messageHash = await hashMessage(VALID_MESSAGE);
    expect(viewHash.bytes).toEqual(messageHash.bytes);
  });

  it("returns a consistent hash for the same key", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const h1 = Uint8ArrayToBase64((await hashKey(key)).bytes);
    const h2 = Uint8ArrayToBase64((await hashKey(key)).bytes);
    expect(h1).toBe(h2);
  });

  it("returns the expected base64 SHA-256 hash for known key", async () => {
    const key = await importKey(VALID_PUBLIC_KEY);
    const hash = Uint8ArrayToBase64((await hashKey(key)).bytes);
    expect(hash).toBe(EXPECTED_BASE64_HASH);
  });

  it("verifies a valid signed tree head", async () => {
    const publicKey = await importKey(LOG_PUBKEY);
    const logKeyHash = await hashKey(publicKey);

    const treeHead: TreeHead = {
      Size: 899,
      RootHash: TREEHEAD_ROOT_HASH,
    };

    const signedTreeHead: SignedTreeHead = {
      TreeHead: treeHead,
      Signature: TREEHEAD_SIGNATURE,
    };

    const result = await verifySignedTreeHead(
      signedTreeHead,
      publicKey,
      logKeyHash,
    );
    expect(result).toBe(true);
  });

  it("fails to verify if root hash is tampered", async () => {
    const publicKey = await importKey(LOG_PUBKEY);
    const logKeyHash = await hashKey(publicKey);

    const corrupted = TREEHEAD_ROOT_HASH.bytes.slice();
    corrupted[corrupted.length - 1] ^= 0xff;

    const treeHead: TreeHead = {
      Size: 899,
      RootHash: new Hash(corrupted),
    };

    const signedTreeHead: SignedTreeHead = {
      TreeHead: treeHead,
      Signature: TREEHEAD_SIGNATURE,
    };

    const result = await verifySignedTreeHead(
      signedTreeHead,
      publicKey,
      logKeyHash,
    );
    expect(result).toBe(false);
  });

  it("fails to verify if signature is tampered", async () => {
    const publicKey = await importKey(LOG_PUBKEY);
    const logKeyHash = await hashKey(publicKey);

    const corrupted = TREEHEAD_SIGNATURE.bytes.slice();
    corrupted[corrupted.length - 1] ^= 0xff;

    const signedTreeHead: SignedTreeHead = {
      TreeHead: { Size: 899, RootHash: TREEHEAD_ROOT_HASH },
      Signature: new Signature(corrupted),
    };

    const result = await verifySignedTreeHead(
      signedTreeHead,
      publicKey,
      logKeyHash,
    );
    expect(result).toBe(false);
  });

  it("fails to verify if public key is tampered", async () => {
    const corrupted = LOG_PUBKEY.bytes.slice();
    corrupted[corrupted.length - 1] ^= 0xff;

    const publicKey = await importKey(new RawPublicKey(corrupted));
    const logKeyHash = await hashKey(publicKey);

    const signedTreeHead: SignedTreeHead = {
      TreeHead: { Size: 899, RootHash: TREEHEAD_ROOT_HASH },
      Signature: TREEHEAD_SIGNATURE,
    };

    const result = await verifySignedTreeHead(
      signedTreeHead,
      publicKey,
      logKeyHash,
    );
    expect(result).toBe(false);
  });

  it("verifies a valid cosignature", async () => {
    const witnessPublicKey = await importKey(WITNESS_PUBKEY);
    const logPublicKey = await importKey(LOG_PUBKEY);
    const logKeyHash = await hashKey(logPublicKey);

    const treeHead: TreeHead = {
      Size: 899,
      RootHash: TREEHEAD_ROOT_HASH,
    };

    const cosignature: Cosignature = {
      Signature: WITNESS_COSIGNATURE,
      Timestamp: WITNESS_TIMESTAMP,
    };

    const result = await verifyCosignedTreeHead(
      treeHead,
      witnessPublicKey,
      logKeyHash,
      cosignature,
    );
    expect(result).toBe(true);
  });

  it("fails to verify a cosignature with tampered timestamp", async () => {
    const witnessPublicKey = await importKey(WITNESS_PUBKEY);
    const logPublicKey = await importKey(LOG_PUBKEY);
    const logKeyHash = await hashKey(logPublicKey);

    const treeHead: TreeHead = {
      Size: 899,
      RootHash: TREEHEAD_ROOT_HASH,
    };

    const cosignature: Cosignature = {
      Signature: WITNESS_COSIGNATURE,
      Timestamp: WITNESS_TIMESTAMP + 1,
    };

    const result = await verifyCosignedTreeHead(
      treeHead,
      witnessPublicKey,
      logKeyHash,
      cosignature,
    );
    expect(result).toBe(false);
  });

  it("fails when tree size is one and leaf mismatch", async () => {
    const proof = await SigsumProof.fromAscii(PROOF);

    const checksum = await hashMessage(
      (await hashMessage(new Uint8Array([0x1, 0x2]))).bytes,
    );
    const leafHash = await proof.leaf.toLeaf(checksum).hashLeaf();

    await expect(() =>
      verifyInclusionProof(
        leafHash,
        proof.inclusion.LeafIndex,
        proof.treeHead.SignedTreeHead.TreeHead,
        proof.inclusion.Path,
      ),
    ).rejects.toThrow(/tree size is 1 but leaf does not match/);
  });

  it("rejects an index equal to the tree size", async () => {
    await expect(
      verifyInclusionProof(
        TREEHEAD_ROOT_HASH,
        1,
        { Size: 1, RootHash: TREEHEAD_ROOT_HASH },
        [],
      ),
    ).rejects.toThrow(/index out of range/);
  });

  it("verifies tree sizes above the signed 32-bit range", async () => {
    const leaf = await hashMessage(new Uint8Array([0]));
    const path: Hash[] = [];
    let root = leaf;
    for (let i = 0; i < 32; i++) {
      const sibling = await hashMessage(new Uint8Array([i + 1]));
      path.push(sibling);
      root = await hashInteriorNode(root, sibling);
    }

    await expect(
      verifyInclusionProof(leaf, 0, { Size: 2 ** 31 + 1, RootHash: root }, path),
    ).resolves.toBe(true);
  });
});

describe("constantTimeBufferEqual", () => {
  it("returns false for different lengths", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeBufferEqual(a, b)).toBe(false);
  });

  it("returns true for same content", () => {
    const a = new Uint8Array([5, 6, 7]);
    const b = new Uint8Array([5, 6, 7]);
    expect(constantTimeBufferEqual(a, b)).toBe(true);
  });

  it("returns false for same length but different content", () => {
    const a = new Uint8Array([5, 6, 7]);
    const b = new Uint8Array([5, 9, 7]);
    expect(constantTimeBufferEqual(a, b)).toBe(false);
  });
});
