import { beforeAll, describe, expect, it } from "vitest";

import { hexToUint8Array } from "../encoding";
import { compilePolicy } from "../policyCompiler";
import { RawPublicKey } from "../types";
import {
  verifyHash,
  verifyMessage,
  verifyMessageWithCompiledPolicy,
} from "../verify";

type VerifierFn = (
  message: Uint8Array,
  submitterKey: RawPublicKey,
  policyOrCompiled: string | Uint8Array,
  proofText: string,
) => Promise<boolean>;

const POLICY = `
log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness test1 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness test2 28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806
witness test3 f4855a0f46e8a3e23bb40faf260ee57ab8a18249fa402f2ca2d28a60e1a3130e

group 2of3 2 test1 test2 test3

quorum 2of3`;

const PROOF = `
version=1
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=f62f 00004cce3ad5f54dceb2e20788b72b1c91a8c3913e7866670f5752fe14009f4d 7fdadea21d3268bceb9c4959f25ed8d7a0be2e23637bbcf795b861498626928bcde9180591c5d3c1d6b15b0b6a36df329226d312cde0bb36331888194df1680a

tree_size=930
root_hash=f24ca2b7b234c380438fbeb7e6a3e7481705adf22b8ecab47ca049b31b642bd8
signature=a3e28bf1b8e97664ba2505ed1f02373af70ad86f5a794b8ddf77c9dfc2cda3766479cc53906312dc705f5892472eb1b1a60843f1fd0e0ea3442b6df6a7f11805
cosignature=e923764535cac36836d1af682a2a3e5352e2636ec29c1d34c00160e1f4946d31 1749045854 eb9670fc459a8a3ca226cda1cdc37079018e7e2ae94db426da8e25e181ca29fd651e5ab6e12b3b080fd93cf41304d78669da499744f2c8db8adf25d9fa1ecb0e
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1749045854 62b2733f600df0cf2b2fe6e3e2b5e525048280872b68df3fc4b08409e325c857b5aa4b96806ced5fcb8edf4eb138e13772f48d55cc0de821bb8e6866443e7602
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1749045854 dbf5eb3cb2f7f0bb4f81d748becb2e9ab0454e7fe674722d53963044b53a7105ec6b0dc83fd942f68d6bc5eca37540c837fcef3b657cf920a98e61adcdfc3d08
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1749045854 5c5fa4d25f7734caf519c41b25e40220d54a7b1637cb608a034d7ee7878501313b36c8b8c0e4b61c7bb7d1f123aa856ffdb80e035650eac4b59be0f877d68e00
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1749045854 87c38ca5122a164450c93656a10b36deade0d031501d63ea9377d24608ad0d45949d938129c7e780495332aa09c44f8bf00a08ffe689a470504c25beb8bdfc07

leaf_index=929
node_hash=77c4b148100a011c490dd23bead8e08f9bdafe27675082f6ec00b0725b8ef8fd
node_hash=0736f9e2aad3b8c89c4dbb01f71d3c38d0ace393079dcaf8edd9b61ab9adca84
node_hash=abc5352f9af6df2f2c0a06381043393af36555170c01b3004507af7d36fd22a4
node_hash=4e301e7ae4f9abb0c710cae380daa991b95528b0d631ce04a001c28236e4f938
node_hash=b6be547daa4f6b3d42628bb14020e9b2d73a4ee8cf3c4e0a3b88793916926f27
`;

const EVEN_PROOF = `
version=1
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=2a34 00004cce3ad5f54dceb2e20788b72b1c91a8c3913e7866670f5752fe14009f4d 3e560a2862507ad5c1c3a41738963d2d613c5d39bd2733385bfb78b161565990633f693426f1a927e2611acfb54fe8c4b56813ba0ad02a51cb35f8e2245bfb03

tree_size=1329
root_hash=1c976d814b6feb92ab652982e9ae736fcbb7b25023a1f8e92172270a11cfb082
signature=77d2d05baf593d2a4a1ac4e968cf482aa335856ca401f64630819cd74cf552e8f99a0013b6f984efaf1233022da609b4c9c3531c50cec1ecd6b39f8b0b88d504
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1750089614 1ea63b6b7b4fe26efa8c1b1a23783cafcaf94519ccb55201145e4cfec15a69911b4efdd65c02d5b9adef91cd2df32c96da0e0b4c97e88bc505eb811b4b950901
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1750089614 3788344f8efcc4a2fd646d7af7bba180a394875bb5ea64e8a334a0c1b6cac2f4425997157b77dd7f4f39f60ca3b842157eb6afbe83618e28ca87445a1932a708
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1750089614 dcc153e74c9cae5a721ba2f04ffcbbb0a00c8396299dbe7fee427d17b96d4ee92c2e837cbffa0900604118fdf57f0ad3d0f89c8e5b1a830fdfa1a67dc7323a0d
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1750089614 fc6e1554ca1afc1847f5039b0ba09fffc47d64c24e23be5ceed0f83e0cf5c0c7fe0d2625ad3ea01956c7b05a1688efd941761daaff86bef09fa8275a26063906
cosignature=e923764535cac36836d1af682a2a3e5352e2636ec29c1d34c00160e1f4946d31 1750089614 9ea315932f7fdcae21d890dc90a4133c9ba1b60e5adb68ebfb4c1eba2783e355f3c922f3ee3cf603505ee899143d1d48863df4beab2583e3003c31178624b50d

leaf_index=1326
node_hash=7031dbf9467849fa2669561c0a46c413384344035745a293c1a9e22462e34990
node_hash=3a86b60f941ef825d606adbdddfaf0c8158bc1540f291e2ea9871c1cf2ce21de
node_hash=94c78377d2929a0fdd7951abf6ec5decef32489ecbcf4662c47877f74ab1bd93
node_hash=9ad424733d201c3ba25c95e3530e7757e882c97b269176631bfc881bf2330481
node_hash=92cb11a484ce31f2b158ce44c5d94318cca9aa1e053ac8e6da61b831cf9c0fc4
node_hash=84f6866ee5995260b5241339d1cc1f00d5ceef09a1b542fac6dc14851e3bc8ab
node_hash=e98d0bea1c434584cdd86613bec52dc75366d25a8b586e9200d587f0685104dc
node_hash=bf05c324a46a39bbc4c12d0d931784efaa6e1864dae47e1baf2dbfe761b35b48
`;

const PUBKEY = new RawPublicKey(
  hexToUint8Array(
    `236bb3cff541f16b1c357624d20f258cc48b7c57080ff7de60c971df70c04ad8`,
  ),
);

// test\n
const MESSAGE = new Uint8Array([0x74, 0x65, 0x73, 0x74, 0x0a]);
// test2\n
const MESSAGE2 = new Uint8Array([0x74, 0x65, 0x73, 0x74, 0x32, 0x0a]);

let compiled: Uint8Array;

beforeAll(async () => {
  compiled = await compilePolicy(POLICY);
});

// Parameterized verifier definition
const verifierText: VerifierFn = async (msg, key, policy, proof) =>
  verifyMessage(msg, key, policy as string, proof);

const verifierCompiled: VerifierFn = async (msg, key, _unused, proof) =>
  verifyMessageWithCompiledPolicy(msg, key, compiled, proof);

describe.each([
  ["text policy", verifierText],
  ["compiled policy", verifierCompiled],
])("verify (%s)", (_label, verifyFn) => {
  it("runs a successful verification (odd leaf, last included)", async () => {
    expect(await verifyFn(MESSAGE, PUBKEY, POLICY, PROOF)).toBe(true);
  });

  it("runs a successful verification (even leaf, middle position)", async () => {
    expect(await verifyFn(MESSAGE2, PUBKEY, POLICY, EVEN_PROOF)).toBe(true);
  });

  it("fails for a tampered message", async () => {
    const fake = new Uint8Array([0x75, 0x65, 0x73, 0x74, 0x0a]);
    await expect(() => verifyFn(fake, PUBKEY, POLICY, PROOF)).rejects.toThrow(
      /invalid message signature/,
    );
  });

  it("fails for a leaf index larger than the tree size", async () => {
    const tooHigh = PROOF.replace("leaf_index=929", "leaf_index=931");
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, tooHigh),
    ).rejects.toThrow(/out of range/);
  });

  it("fails for a tampered inclusion path", async () => {
    const tampered = PROOF.replace(
      "node_hash=4e301e7ae4f9abb0c710cae380daa991b95528b0d631ce04a001c28236e4f938",
      "node_hash=aa301e7ae4f9abb0c710cae380daa991b95528b0d631ce04a001c28236e4f938",
    );
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, tampered),
    ).rejects.toThrow(/invalid proof|inclusion/i);
  });

  it("fails for an inclusion path that is too long", async () => {
    const overlong = PROOF.concat(
      "node_hash=236bb3cff541f16b1c357624d20f258cc48b7c57080ff7de60c971df70c04ad8\n",
    );
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, overlong),
    ).rejects.toThrow(/unused path|internal error/i);
  });

  it("fails for a log not in the policy", async () => {
    const wrongLog = PROOF.replace(
      "log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d",
      "log=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, wrongLog),
    ).rejects.toThrow(/log key not found/i);
  });

  it("fails for a proof from a different keyhash", async () => {
    const wrongKey = PROOF.replace(
      "00004cce3ad5f54dceb2e20788b72b1c91a8c3913e7866670f5752fe14009f4d",
      "aa004cce3ad5f54dceb2e20788b72b1c91a8c3913e7866670f5752fe14009f4d",
    );
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, wrongKey),
    ).rejects.toThrow(/proof key does not match/i);
  });

  it("fails for tampered tree size", async () => {
    const tampered = PROOF.replace("tree_size=930", "tree_size=931");
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, tampered),
    ).rejects.toThrow(/failed to verify tree head signature/i);
  });

  it("fails for tampered tree hash", async () => {
    const tampered = PROOF.replace(
      "root_hash=f24ca2b7b234c380438fbeb7e6a3e7481705adf22b8ecab47ca049b31b642bd8",
      "root_hash=aa4ca2b7b234c380438fbeb7e6a3e7481705adf22b8ecab47ca049b31b642bd8",
    );
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, tampered),
    ).rejects.toThrow(/failed to verify tree head signature/i);
  });

  it("fails for tampered tree signature", async () => {
    const tampered = PROOF.replace(
      "signature=a3e28bf1b8e97664ba2505ed1f02373af70ad86f5a794b8ddf77c9dfc2cda3766479cc53906312dc705f5892472eb1b1a60843f1fd0e0ea3442b6df6a7f11805",
      "signature=bbe28bf1b8e97664ba2505ed1f02373af70ad86f5a794b8ddf77c9dfc2cda3766479cc53906312dc705f5892472eb1b1a60843f1fd0e0ea3442b6df6a7f11805",
    );
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, tampered),
    ).rejects.toThrow(/failed to verify tree head signature/i);
  });

  it("fails for not enough cosignatures", async () => {
    const failQuorum = `
version=1
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=f62f 00004cce3ad5f54dceb2e20788b72b1c91a8c3913e7866670f5752fe14009f4d 7fdadea21d3268bceb9c4959f25ed8d7a0be2e23637bbcf795b861498626928bcde9180591c5d3c1d6b15b0b6a36df329226d312cde0bb36331888194df1680a

tree_size=930
root_hash=f24ca2b7b234c380438fbeb7e6a3e7481705adf22b8ecab47ca049b31b642bd8
signature=a3e28bf1b8e97664ba2505ed1f02373af70ad86f5a794b8ddf77c9dfc2cda3766479cc53906312dc705f5892472eb1b1a60843f1fd0e0ea3442b6df6a7f11805
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1749045854 62b2733f600df0cf2b2fe6e3e2b5e525048280872b68df3fc4b08409e325c857b5aa4b96806ced5fcb8edf4eb138e13772f48d55cc0de821bb8e6866443e7602

leaf_index=929
node_hash=77c4b148100a011c490dd23bead8e08f9bdafe27675082f6ec00b0725b8ef8fd
node_hash=0736f9e2aad3b8c89c4dbb01f71d3c38d0ace393079dcaf8edd9b61ab9adca84
node_hash=abc5352f9af6df2f2c0a06381043393af36555170c01b3004507af7d36fd22a4
node_hash=4e301e7ae4f9abb0c710cae380daa991b95528b0d631ce04a001c28236e4f938
node_hash=b6be547daa4f6b3d42628bb14020e9b2d73a4ee8cf3c4e0a3b88793916926f27
`;
    await expect(() =>
      verifyFn(MESSAGE, PUBKEY, POLICY, failQuorum),
    ).rejects.toThrow(/cosignature quorum not satisfied/i);
  });
});

it("rejects a message hash with the wrong length", async () => {
  await expect(
    verifyHash(new Uint8Array(31), PUBKEY, POLICY, PROOF),
  ).rejects.toThrow("message hash must be exactly 32 bytes");
});
