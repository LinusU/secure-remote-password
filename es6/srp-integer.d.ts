import { BigInteger } from 'jsbn';
declare const kBigInteger: unique symbol;
declare const kHexLength: unique symbol;
declare class SRPInteger {
    [kBigInteger]: BigInteger;
    [kHexLength]: number | null;
    static fromHex: (input: string) => SRPInteger;
    static randomInteger: (bytes: number) => SRPInteger;
    static ZERO: SRPInteger;
    constructor(bigInteger: BigInteger, hexLength: number | null);
    add(val: SRPInteger): SRPInteger;
    equals(val: SRPInteger): boolean;
    multiply(val: SRPInteger): SRPInteger;
    modPow(exponent: SRPInteger, m: SRPInteger): SRPInteger;
    mod(m: SRPInteger): SRPInteger;
    subtract(val: SRPInteger): SRPInteger;
    xor(val: SRPInteger): SRPInteger;
    inspect(): string;
    toHex(): string;
}
export default SRPInteger;
