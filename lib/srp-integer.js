'use strict'

const padStart = require('pad-start')
const randomHex = require('crypto-random-hex')
const { BigInteger } = require('jsbn')

const kBigInteger = Symbol('big-integer')
const kHexLength = Symbol('hex-length')

class SRPInteger {
  constructor (bigInteger, hexLength) {
    this[kBigInteger] = bigInteger
    this[kHexLength] = hexLength
  }

  add (val) {
    return new SRPInteger(this[kBigInteger].add(val[kBigInteger]), null)
  }

  equals (val) {
    return this[kBigInteger].equals(val[kBigInteger])
  }

  multiply (val) {
    return new SRPInteger(this[kBigInteger].multiply(val[kBigInteger]), null)
  }

  modPow (exponent, m) {
    return new SRPInteger(this[kBigInteger].modPow(exponent[kBigInteger], m[kBigInteger]), m[kHexLength])
  }

  mod (m) {
    return new SRPInteger(this[kBigInteger].mod(m[kBigInteger]), m[kHexLength])
  }

  subtract (val) {
    return new SRPInteger(this[kBigInteger].subtract(val[kBigInteger]), this[kHexLength])
  }

  xor (val) {
    return new SRPInteger(this[kBigInteger].xor(val[kBigInteger]), this[kHexLength])
  }

  pad (hexLength) {
    if (hexLength < this[kHexLength]) {
      throw new Error('Cannot pad to a shorter length')
    }

    return new SRPInteger(this[kBigInteger], hexLength)
  }

  inspect () {
    const hex = this[kBigInteger].toString(16)

    return `<SRPInteger ${hex.slice(0, 16)}${hex.length > 16 ? '...' : ''}>`
  }

  toHex () {
    if (this[kHexLength] === null) {
      throw new Error('This SRPInteger has no specified length')
    }

    return padStart(this[kBigInteger].toString(16), this[kHexLength], '0')
  }
}

SRPInteger.fromHex = function (input) {
  return new SRPInteger(new BigInteger(input, 16), input.length)
}

SRPInteger.randomInteger = function (bytes) {
  return SRPInteger.fromHex(randomHex(bytes))
}

SRPInteger.ZERO = new SRPInteger(new BigInteger('0'), null)

module.exports = SRPInteger
