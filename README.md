# sigsum-ts

_Note: this library has not been audited, thus its security has not been independently verified._

`sigsum-ts` is a small TypeScript library for verifying Sigsum proofs in the browser. It is designed to work with the Sigsum policy format and verify inclusion proofs, Signed Tree Heads, and cosignatures according to quorum rules. The implementation is strictly for verification purposes, and any cryptographic or format error will throw an exception, ensuring that failures are always explicit and must be caught by the caller. Its only runtime dependency is [crypto-browser](https://github.com/freedomofpress/crypto-browser), which uses the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) and falls back to a pure implementation for Ed25519 where the engine lacks it. The library mirrors the logic of the original Go implementation from the Sigsum repository, and aims to be as close in behavior and structure as possible.

`sigsum-ts` has complete test coverage. Its primary use case is as part of [WEBCAT](https://github.com/freedomofpress/webcat), a transparency and integrity layer for web-based applications, where client-side verification of cryptographic proofs is required.

For more information on Sigsum visit the [sigsum.org](https://sigsum.org) or the [development repository](https://git.glasklar.is/sigsum/core/sigsum-go).

## Nominal crypto types

To prevent accidental misuse of cryptographic material, `sigsum-ts` defines explicit nominal wrapper classes for each crypto type. Although many of them internally wrap a `Uint8Array` or a `string`, they are not interchangeable, and TypeScript will refuse to pass a `Hash` where a `Signature` is expected.

## Usage

To verify a Sigsum proof, call the verifyMessage() function with the message, the raw submitter public key, a Sigsum policy, and the proof text.

```ts
import { verifyMessage } from "sigsum-ts";

const isValid = await verify(
  messageBytes, // Uint8Array
  submitterRawPublicKey, // Uint8Array as RawPublicKey (32 bytes, Ed25519)
  policyText, // string (Sigsum policy format)
  proofText, // string (Sigsum proof format)
);
```

Sometimes, especially when fetching updates remotely, it could be useful to verify a proof for a hash of a file that has not been obtained yet. `verifyHash` takes the same arguments of `verifyMessage`, except that the first one is expected to be already an hash.

```ts
import { verifyMessage } from "sigsum-ts";

const isValid = await verifyMessage(
  messageHash, // Uint8Array
  submitterRawPublicKey, // Uint8Array as RawPublicKey (32 bytes, Ed25519)
  policyText, // string (Sigsum policy format)
  proofText, // string (Sigsum proof format)
);
```

## Experimental policy compilation & evaluation

This project includes a policy compiler and bytecode-based evaluator adapted from the [Sigsum C](https://git.glasklar.is/nisse/sigsum-c) reference implementation. The goal is to make policy verification compact and efficient, suitable for constrained environments with limited memory and binary size requirements (e.g., embedded devices).

Both the compiled format and the evaluation logic are experimental and unstable as they may change without notice as the Sigsum ecosystem evolves.

References:

- [Sigsum and Tillitis TKey – Exploring transparency apps](https://www.glasklarteknik.se/post/exploring-transparency-apps-tkey/)
- [sigsum-compile-policy.c](https://git.glasklar.is/nisse/sigsum-c/-/blob/main/tools/sigsum-compile-policy.c)
- [verify.c](https://git.glasklar.is/nisse/sigsum-c/-/blob/main/lib/verify.c)
