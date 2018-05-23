'use strict'

const params = require('./lib/params')
const SRPInteger = require('./lib/srp-integer')

exports.generateEphemeral = function (verifier) {
  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  // k      Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  const { N, g, k } = params

  // v      Password verifier
  const v = SRPInteger.fromHex(verifier)

  // B = kv + g^b             (b = random number)
  const b = SRPInteger.randomInteger(params.hashOutputBytes)
  const B = k.multiply(v).add(g.modPow(b, N)).mod(N)

  return {
    secret: b.toHex(),
    public: B.toHex()
  }
}

exports.deriveSession = function (serverSecretEphemeral, clientPublicEphemeral, salt, username, verifier, clientSessionProof) {
  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  // k      Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  // H()    One-way hash function
  // PAD()  Pad the number to have the same number of bytes as N
  const { N, g, k, H, PAD } = params

  // b      Secret ephemeral values
  // A      Public ephemeral values
  // s      User's salt
  // p      Cleartext Password
  // I      Username
  // v      Password verifier
  const b = SRPInteger.fromHex(serverSecretEphemeral)
  const A = SRPInteger.fromHex(clientPublicEphemeral)
  const s = SRPInteger.fromHex(salt)
  const I = String(username)
  const v = SRPInteger.fromHex(verifier)

  // B = kv + g^b             (b = random number)
  const B = k.multiply(v).add(g.modPow(b, N)).mod(N)

  // A % N > 0
  if (A.mod(N).equals(SRPInteger.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('The client sent an invalid public ephemeral')
  }

  // u = H(PAD(A), PAD(B))
  const u = H(PAD(A), PAD(B))

  // S = (Av^u) ^ b              (computes session key)
  const S = A.multiply(v.modPow(u, N)).modPow(b, N)

  // K = H(S)
  const K = H(S)

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = H(H(N).xor(H(g)), H(I), s, A, B, K)

  const expected = M
  const actual = SRPInteger.fromHex(clientSessionProof)

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('Client provided session proof is invalid')
  }

  // P = H(A, M, K)
  const P = H(A, M, K)

  return {
    key: K.toHex(),
    proof: P.toHex()
  }
}
