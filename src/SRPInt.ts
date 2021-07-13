import { BigInteger } from "jsbn";
import { bufferToHex } from "./buffer";
import { crypto } from "./crypto";

const bi = Symbol("big-int");
const hl = Symbol("hex-length");

export class SRPInt {
  [bi]: BigInteger;
  [hl]: number | null;

  constructor(bigInteger: BigInteger, hexLength: number | null) {
    this[bi] = bigInteger;
    this[hl] = hexLength;
  }

  static ZERO = new SRPInt(new BigInteger("0"), null);

  static randomInteger(bytes: number) {
    const view = new Uint8Array(bytes);
    crypto.getRandomValues(view);
    return SRPInt.fromHex(bufferToHex(view.buffer));
  }

  static fromHex(input: string) {
    return new SRPInt(new BigInteger(input, 16), input.length);
  }

  toHex() {
    const maxLength = this[hl];

    if (maxLength === null) {
      throw new Error("This SRPInt has no specified length");
    }

    return this[bi].toString(16).padStart(maxLength, "0");
  }

  equals(value: SRPInt) {
    return this[bi].equals(value[bi]);
  }

  add(value: SRPInt) {
    return new SRPInt(this[bi].add(value[bi]), null);
  }

  subtract(value: SRPInt) {
    return new SRPInt(this[bi].subtract(value[bi]), this[hl]);
  }

  multiply(value: SRPInt) {
    return new SRPInt(this[bi].multiply(value[bi]), null);
  }

  xor(value: SRPInt) {
    return new SRPInt(this[bi].xor(value[bi]), this[hl]);
  }

  mod(modulus: SRPInt) {
    return new SRPInt(this[bi].mod(modulus[bi]), modulus[hl]);
  }

  modPow(exponent: SRPInt, modulus: SRPInt) {
    return new SRPInt(this[bi].modPow(exponent[bi], modulus[bi]), modulus[hl]);
  }
}
