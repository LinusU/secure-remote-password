'use strict'

const padStart = require('pad-start')
const { BigInteger } = require('jsbn')

const { params, H, randomInteger } = require('./common')

exports.generateEphemeral = function (verifier) {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  const { N, g, k } = params

  // v    Password verifier
  const v = new BigInteger(verifier, 16)

  // B = kv + g^b             (b = random number)
  const b = randomInteger()
  const B = k.multiply(v).add(g.modPow(b, N))

  return {
    secret: padStart(b.toString(16), params.H_length_bits / 4, '0'),
    public: padStart(B.toString(16), params.N_length_bits / 4, '0')
  }
}

exports.computeSession = function (serverEphemeral, clientPublicEphemeral, salt, username, verifier, clientSessionProof) {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  const { N, g } = params

  // b    Secret ephemeral values
  // A,B  Public ephemeral values
  // s    User's salt
  // p    Cleartext Password
  // I    Username
  // v    Password verifier
  const b = new BigInteger(serverEphemeral.secret, 16)
  const A = new BigInteger(clientPublicEphemeral, 16)
  const B = new BigInteger(serverEphemeral.public, 16)
  const s = new BigInteger(salt, 16)
  const I = String(username)
  const v = new BigInteger(verifier, 16)

  // A % N > 0
  if (A.mod(N).equals(BigInteger.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('The client sent an invalid public ephemeral')
  }

  // u = H(A, B)
  const u = H(A, B)

  // S = (Av^u) ^ b              (computes session key)
  const S = A.multiply(v.modPow(u, N)).modPow(b, N)

  // K = H(S)
  const K = H(S)

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = H(H(N).xor(H(g)), H(I), s, A, B, K)

  const expected = M
  const actual = new BigInteger(clientSessionProof, 16)

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('Client provided session proof is invalid')
  }

  // P = H(A, M, K)
  const P = H(A, M, K)

  return {
    key: padStart(K.toString(16), params.H_length_bits / 4, '0'),
    proof: padStart(P.toString(16), params.H_length_bits / 4, '0')
  }
}
