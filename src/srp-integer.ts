import randomHex from 'crypto-random-hex'
import { BigInteger } from 'jsbn'

const padStart = (str: string, maxLength: number, fillString: string) =>
	str.padStart(maxLength, fillString)

const kBigInteger = Symbol('big-integer')
const kHexLength = Symbol('hex-length')

class SRPInteger {
	[kBigInteger]: BigInteger;
	[kHexLength]: number | null
	static fromHex: (input: string) => SRPInteger
	static randomInteger: (bytes: number) => SRPInteger
	static ZERO: SRPInteger

	constructor(bigInteger: BigInteger, hexLength: number | null) {
		this[kBigInteger] = bigInteger
		this[kHexLength] = hexLength
	}

	add(val: SRPInteger) {
		return new SRPInteger(this[kBigInteger].add(val[kBigInteger]), null)
	}

	equals(val: SRPInteger) {
		return this[kBigInteger].equals(val[kBigInteger])
	}

	multiply(val: SRPInteger) {
		return new SRPInteger(
			this[kBigInteger].multiply(val[kBigInteger]),
			null
		)
	}

	modPow(exponent: SRPInteger, m: SRPInteger) {
		return new SRPInteger(
			this[kBigInteger].modPow(exponent[kBigInteger], m[kBigInteger]),
			m[kHexLength]
		)
	}

	mod(m: SRPInteger) {
		return new SRPInteger(
			this[kBigInteger].mod(m[kBigInteger]),
			m[kHexLength]
		)
	}

	subtract(val: SRPInteger) {
		return new SRPInteger(
			this[kBigInteger].subtract(val[kBigInteger]),
			this[kHexLength]
		)
	}

	xor(val: SRPInteger) {
		return new SRPInteger(
			this[kBigInteger].xor(val[kBigInteger]),
			this[kHexLength]
		)
	}

	inspect() {
		const hex = this[kBigInteger].toString(16)

		return `<SRPInteger ${hex.slice(0, 16)}${hex.length > 16 ? '...' : ''}>`
	}

	toHex() {
		if (this[kHexLength] === null) {
			throw new Error('This SRPInteger has no specified length')
		}

		return padStart(
			this[kBigInteger].toString(16),
			this[kHexLength] ?? 0,
			'0'
		)
	}
}

SRPInteger.fromHex = function (input: string) {
	return new SRPInteger(new BigInteger(input, 16), input.length)
}

SRPInteger.randomInteger = function (bytes: number) {
	return SRPInteger.fromHex(randomHex(bytes))
}

SRPInteger.ZERO = new SRPInteger(new BigInteger('0'), null)

export default SRPInteger
