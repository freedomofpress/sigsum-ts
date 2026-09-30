import { describe, expect, it } from "vitest";

import {
  hexToBase64,
  hexToUint8Array,
  stringToUint8Array,
  Uint8ArrayToBase64,
  Uint8ArrayToHex,
} from "../encoding.js";

describe("encoding", () => {
  it("converts Uint8Array to Base64", () => {
    const input = new Uint8Array([72, 101, 108, 108, 111]);
    const result = Uint8ArrayToBase64(input);
    expect(result).toBe("SGVsbG8=");
  });

  it("converts ArrayBuffer to Base64", () => {
    const buffer = new TextEncoder().encode("Hi").buffer;
    const result = Uint8ArrayToBase64(buffer);
    expect(result).toBe("SGk=");
  });

  it("parses valid hex string", () => {
    const hex = "48656c6c6f";
    const uint8 = hexToUint8Array(hex);
    expect([...uint8]).toEqual([72, 101, 108, 108, 111]);
  });

  it("throws on invalid characters", () => {
    expect(() => hexToUint8Array("zz12")).toThrow(
      "Hex string contains invalid characters",
    );
  });

  it("throws on odd-length hex string", () => {
    expect(() => hexToUint8Array("abc")).toThrow(
      "Hex string must have an even length",
    );
  });

  it("encodes Uint8Array to hex string", () => {
    const input = new Uint8Array([72, 101, 108, 108, 111]);
    const hex = Uint8ArrayToHex(input);
    expect(hex).toBe("48656c6c6f");
  });

  it("encodes string to Uint8Array", () => {
    const result = stringToUint8Array("Hi");
    expect([...result]).toEqual([72, 105]);
  });

  it("converts hex string to Base64", () => {
    const hex = "48656c6c6f";
    const base64 = hexToBase64(hex);
    expect(base64).toBe("SGVsbG8=");
  });
});
