'use strict'

const padStart = require('pad-start')
const { BigInteger } = require('jsbn')

const { params, H, randomInteger } = require('./common')

exports.generateSalt = function () {
  // s    User's salt
  const s = randomInteger()

  return padStart(s.toString(16), params.H_length_bits / 4, '0')
}

exports.computeVerifier = function (username, password, salt) {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  const { N, g } = params

  // s    User's salt
  // I    Username
  // p    Cleartext Password
  const s = new BigInteger(salt, 16)
  const I = String(username)
  const p = String(password)

  // x = H(s, H(I | ':' | p))  (s is chosen randomly)
  const x = H(s, H(`${I}:${p}`))

  // v = g^x                   (computes password verifier)
  const v = g.modPow(x, N)

  return padStart(v.toString(16), params.N_length_bits / 4, '0')
}

exports.generateEphemeral = function () {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  const { N, g } = params

  // A = g^a                  (a = random number)
  const a = randomInteger()
  const A = g.modPow(a, N)

  return {
    secret: padStart(a.toString(16), params.H_length_bits / 4, '0'),
    public: padStart(A.toString(16), params.N_length_bits / 4, '0')
  }
}

exports.computeSession = function (clientEphemeral, serverPublicEphemeral, salt, username, password) {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  const { N, g, k } = params

  // a    Secret ephemeral values
  // A,B  Public ephemeral values
  // s    User's salt
  // p    Cleartext Password
  // I    Username
  const a = new BigInteger(clientEphemeral.secret, 16)
  const A = new BigInteger(clientEphemeral.public, 16)
  const B = new BigInteger(serverPublicEphemeral, 16)
  const s = new BigInteger(salt, 16)
  const p = String(password)
  const I = String(username)

  // B % N > 0
  if (B.mod(N).equals(BigInteger.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('The server sent an invalid public ephemeral')
  }

  // u = H(A, B)
  const u = H(A, B)

  // x = H(s, H(I | ':' | p))  (user enters password)
  const x = H(s, H(`${I}:${p}`))

  // S = (B - kg^x) ^ (a + ux)
  const S = B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)

  // K = H(S)
  const K = H(S)

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = H(H(N).xor(H(g)), H(I), s, A, B, K)

  return {
    key: padStart(K.toString(16), params.H_length_bits / 4, '0'),
    proof: padStart(M.toString(16), params.H_length_bits / 4, '0')
  }
}

exports.verifySession = function (clientEphemeral, clientSession, serverSessionProof) {
  // A    Public ephemeral values
  // M    Proof of K
  // K    Shared, strong session key
  const A = new BigInteger(clientEphemeral.public, 16)
  const M = new BigInteger(clientSession.proof, 16)
  const K = new BigInteger(clientSession.key, 16)

  // H(A, M, K)
  const expected = H(A, M, K)
  const actual = new BigInteger(serverSessionProof, 16)

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('Server provided session proof is invalid')
  }
}
