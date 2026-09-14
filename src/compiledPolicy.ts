import { hashKey, importKey } from "./crypto";
import { Uint8ArrayToBase64 } from "./encoding";
import { Base64KeyHash, KeyHash, PublicKey, RawPublicKey } from "./types";

const DEFAULT_RAW_PUBKEY_LEN = 32;

export interface CompiledPolicy {
  version: number;
  logsRaw: Uint8Array[]; // raw public keys
  witnessesRaw: Uint8Array[]; // raw public keys
  quorum: Uint8Array; // bytecode
}

export function parseCompiledPolicy(
  buf: Uint8Array,
  rawPubLen = DEFAULT_RAW_PUBKEY_LEN,
): CompiledPolicy {
  if (buf.length < 4) throw new Error("compiled policy too short");
  if (!Number.isSafeInteger(rawPubLen) || rawPubLen < 1) {
    throw new Error("invalid raw public key length");
  }
  const version = buf[0];
  if (version !== 0) {
    throw new Error(`unsupported compiled policy version ${version}`);
  }
  const nLogs = buf[1];
  const nWitnesses = buf[2];
  const quorumLen = buf[3];

  let off = 4;

  const expect = (n: number) => {
    if (off + n > buf.length) throw new Error("compiled policy truncated");
  };

  // logs
  const logsRaw: Uint8Array[] = [];
  expect(nLogs * rawPubLen);
  for (let i = 0; i < nLogs; i++) {
    logsRaw.push(buf.slice(off, off + rawPubLen));
    off += rawPubLen;
  }

  // witnesses
  const witnessesRaw: Uint8Array[] = [];
  expect(nWitnesses * rawPubLen);
  for (let i = 0; i < nWitnesses; i++) {
    witnessesRaw.push(buf.slice(off, off + rawPubLen));
    off += rawPubLen;
  }

  // quorum bytecode
  expect(quorumLen);
  const quorum = buf.slice(off, off + quorumLen);
  off += quorumLen;
  if (off !== buf.length) throw new Error("compiled policy has trailing data");

  return { version, logsRaw, witnessesRaw, quorum };
}

type HashedKey = {
  pub: PublicKey;
  raw: RawPublicKey;
  hash: KeyHash;
  b64: Base64KeyHash;
};

export async function importAndHashAll(
  raws: Uint8Array[],
): Promise<HashedKey[]> {
  const out: HashedKey[] = [];
  const seen = new Set<string>();
  for (const rawBytes of raws) {
    const raw = new RawPublicKey(rawBytes);
    const pub = await importKey(raw);
    const hash = await hashKey(pub);
    const b64 = new Base64KeyHash(Uint8ArrayToBase64(hash.bytes));
    if (seen.has(b64.value)) {
      throw new Error("compiled policy contains duplicate public keys");
    }
    seen.add(b64.value);
    out.push({
      pub,
      raw,
      hash,
      b64,
    });
  }
  out.sort((a, b) => {
    const A = a.hash.bytes;
    const B = b.hash.bytes;
    for (let i = 0; i < A.length && i < B.length; i++) {
      if (A[i] !== B[i]) return A[i] - B[i];
    }
    return A.length - B.length;
  });
  return out;
}

// Evaluate quorum bytecode like the C
// Byte layout:
//  - top 2 bits are the opcode "class"
//    00: special (only 0x01 = ADD is valid here)
//    01: witness reference (push witnesses[id])
//    10: threshold (>= K) (fold top stack entry to 0/1)
//    11: prefix continuation for multi-byte ids/K
//
// Stack is an array of unsigned bytes.
export function evalQuorumBytecode(
  quorum: Uint8Array,
  nwitnesses: number,
  found: Uint8Array,
  scratch?: Uint8Array,
): boolean {
  if (quorum.length === 0) return true;
  const stack = scratch ?? new Uint8Array(Math.max(1, quorum.length));
  let sp = 0;
  let prefix = 0 >>> 0;

  const push = (v: number) => {
    stack[sp++] = v & 0xff;
  };

  const pop1 = (): number => {
    if (sp === 0) {
      throw new Error("stack underflow");
    }

    sp--;
    return stack[sp];
  };

  for (let i = 0; i < quorum.length; i++) {
    const instr = quorum[i];
    const cls = instr >>> 6;
    const low = instr & 0x3f;

    switch (cls) {
      case 0: {
        if (prefix !== 0) return false;
        if (instr === 0x01) {
          if (sp < 2) return false;
          const a = pop1();
          const b = pop1();
          const s = (a + b) & 0xff;
          // Reject uint8 overflow.
          if (s < a || s < b) return false;
          push(s);
        } else {
          return false;
        }
        break;
      }

      case 1: {
        if (prefix > 0x03ffffff) return false;
        const id = ((prefix << 6) | low) >>> 0;
        prefix = 0;
        if (id >= nwitnesses) return false;
        push(found[id]);
        break;
      }

      case 2: {
        if (prefix > 0x03ffffff) return false;
        if (sp < 1) return false;
        const k = ((prefix << 6) | low) >>> 0;
        prefix = 0;
        const top = pop1();
        push(top >= k ? 1 : 0);
        break;
      }

      case 3: {
        if ((prefix === 0 && low === 0) || prefix > 0x03ffffff) return false;
        prefix = ((prefix << 6) | low) >>> 0;
        continue;
      }
    }
  }

  return prefix === 0 && sp === 1 && stack[0] === 1;
}
