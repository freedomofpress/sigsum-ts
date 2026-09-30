// https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/pkg/policy/policy.go

import { Base64KeyHash, PublicKey } from "./types.js";

export interface Entity {
  publicKey: PublicKey;
  url?: string;
}

export type EntityMap = Map<Base64KeyHash, Entity>;

export interface Quorum {
  isQuorum(present: Set<Base64KeyHash>): boolean;
}

export interface Policy {
  logs: EntityMap;
  witnesses: EntityMap;
  quorum: Quorum;
}

export class QuorumSingle implements Quorum {
  constructor(private readonly w: Base64KeyHash) {}

  isQuorum(present: Set<Base64KeyHash>): boolean {
    return present.has(this.w);
  }

  get witness(): Base64KeyHash {
    return this.w;
  }
}

export class QuorumKofN implements Quorum {
  constructor(
    private readonly subQuorums: Quorum[],
    private readonly k: number,
  ) {}

  isQuorum(present: Set<Base64KeyHash>): boolean {
    let count = 0;
    for (const sq of this.subQuorums) {
      if (sq.isQuorum(present)) count++;
    }
    return count >= this.k;
  }

  get members(): readonly Quorum[] {
    return this.subQuorums;
  }

  get threshold(): number {
    return this.k;
  }
}

export function isQuorumSingle(q: Quorum): q is QuorumSingle {
  return q instanceof QuorumSingle;
}

export function isQuorumKofN(q: Quorum): q is QuorumKofN {
  return q instanceof QuorumKofN;
}
