import { concatBytes, sha256 } from "@freedomofpress/crypto-browser";

export abstract class ByteValue {
  readonly bytes: Uint8Array;

  protected constructor(bytes: Uint8Array | ArrayBuffer) {
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  }
}

/**
 * Represents a public key hash (32 bytes, SHA-256 of raw public key)
 */
export class KeyHash extends ByteValue {
  constructor(bytes: Uint8Array | ArrayBuffer) {
    super(bytes);
  }
}

/**
 * Represents a Merkle tree hash (32 bytes)
 */
export class Hash extends ByteValue {
  constructor(bytes: Uint8Array | ArrayBuffer) {
    super(bytes);
  }
}

/**
 * Ed25519 64-byte signature
 */
export class Signature extends ByteValue {
  constructor(bytes: Uint8Array | ArrayBuffer) {
    super(bytes);
  }
}

/**
 * Raw Ed25519 public key (32 bytes)
 */
export class RawPublicKey extends ByteValue {
  constructor(bytes: Uint8Array | ArrayBuffer) {
    super(bytes);
  }
}

/**
 * WebCrypto CryptoKey wrapper
 */
export class PublicKey {
  readonly key: CryptoKey;

  constructor(key: CryptoKey) {
    this.key = key;
  }
}

/**
 * Base64 encoded KeyHash
 */
export class Base64KeyHash {
  readonly value: string;

  constructor(value: string) {
    this.value = value;
  }

  /**
   * Compare this key to another Base64KeyHash or a string.
   * This allows Map lookup by value instead of object identity.
   */
  equals(other: Base64KeyHash | string): boolean {
    return this.value === (typeof other === "string" ? other : other.value);
  }

  /**
   * Helper: lookup in a Map<Base64KeyHash, T> by Base64KeyHash or string
   */
  static lookup<T>(
    map: Map<Base64KeyHash, T>,
    key: Base64KeyHash | string,
  ): T | undefined {
    for (const [k, v] of map.entries()) {
      if (k.equals(key)) return v;
    }
    return undefined;
  }
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/tree_head.go
export interface Cosignature {
  Timestamp: number;
  Signature: Signature;
}

export interface TreeHead {
  Size: number;
  RootHash: Hash;
}

export interface SignedTreeHead {
  TreeHead: TreeHead;
  Signature: Signature;
}

export interface CosignedTreeHead {
  SignedTreeHead: SignedTreeHead;
  Cosignatures: Map<Base64KeyHash, Cosignature>;
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/leaf.go
export class Leaf {
  readonly checksum: Hash;
  readonly signature: Signature;
  readonly keyHash: KeyHash;

  constructor(checksum: Hash, signature: Signature, keyHash: KeyHash) {
    this.checksum = checksum;
    this.signature = signature;
    this.keyHash = keyHash;
  }

  /**
   * Return the raw leaf bytes, prefixed with the leaf node identifier.
   *
   * Layout (129 bytes):
   *   [0]            PrefixLeafNode (0x00)
   *   [1..32]        checksum (32 bytes)
   *   [33..96]       signature (64 bytes)
   *   [97..128]      key hash (32 bytes)
   */
  public toBytes(): Uint8Array {
    return concatBytes(
      new Uint8Array([0]), // PrefixLeafNode
      this.checksum.bytes,
      this.signature.bytes,
      this.keyHash.bytes,
    );
  }

  public async hashLeaf(): Promise<Hash> {
    const digest = await sha256(this.toBytes());
    return new Hash(digest);
  }
}

// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/types/proof.go
export interface InclusionProof {
  LeafIndex: number;
  Path: Hash[];
}

// See https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/proof/proof.go
export class ShortLeaf {
  KeyHash: KeyHash;
  Signature: Signature;

  constructor(keyHash: KeyHash, signature: Signature) {
    this.KeyHash = keyHash;
    this.Signature = signature;
  }

  //static fromLeaf(leaf: Leaf): ShortLeaf {
  //  return new ShortLeaf(leaf.KeyHash, leaf.Signature);
  //}

  toLeaf(checksum: Hash): Leaf {
    return new Leaf(checksum, this.Signature, this.KeyHash);
  }
}
