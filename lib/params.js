'use strict'

const sha256 = require('./sha256')
const SRPInteger = require('./srp-integer')

const input = {
  largeSafePrime: `
    AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
    3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
    CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
    D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
    7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
    436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
    5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
    03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
    94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
    9E4AFF73
  `,
  generatorModulo: '02',
  hashFunction: 'sha256',
  hashOutputBytes: (256 / 8),
  paddedLength: 512
}

/**
 * @param {SRPInteger} integer
 */
function pad (integer) {
  return integer.pad(input.paddedLength)
}

// N      A large safe prime (N = 2q+1, where q is prime)
// g      A generator modulo N
// k      Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
// H()    One-way hash function
// PAD()  Pad the number to have the same number of bytes as N
exports.N = SRPInteger.fromHex(input.largeSafePrime.replace(/\s+/g, ''))
exports.g = SRPInteger.fromHex(input.generatorModulo.replace(/\s+/g, ''))
exports.k = sha256(exports.N, pad(exports.g))
exports.H = sha256
exports.PAD = pad

exports.hashOutputBytes = input.hashOutputBytes
