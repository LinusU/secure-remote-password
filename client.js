'use strict'

const params = require('./lib/params')
const SRPInteger = require('./lib/srp-integer')

exports.generateSalt = function () {
  // s    User's salt
  const s = SRPInteger.randomInteger()

  return s.toHex()
}

exports.deriveVerifier = function (username, password, salt) {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // H()  One-way hash function
  const { N, g, H } = params

  // s    User's salt
  // I    Username
  // p    Cleartext Password
  const s = SRPInteger.fromHex(salt)
  const I = String(username)
  const p = String(password)

  // x = H(s, H(I | ':' | p))  (s is chosen randomly)
  const x = H(s, H(`${I}:${p}`))

  // v = g^x                   (computes password verifier)
  const v = g.modPow(x, N)

  return v.toHex()
}

exports.generateEphemeral = function () {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  const { N, g } = params

  // A = g^a                  (a = random number)
  const a = SRPInteger.randomInteger()
  const A = g.modPow(a, N)

  return {
    secret: a.toHex(),
    public: A.toHex()
  }
}

exports.deriveSession = function (clientEphemeral, serverPublicEphemeral, salt, username, password) {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  // H()  One-way hash function
  const { N, g, k, H } = params

  // a    Secret ephemeral values
  // A,B  Public ephemeral values
  // s    User's salt
  // p    Cleartext Password
  // I    Username
  const a = SRPInteger.fromHex(clientEphemeral.secret)
  const A = SRPInteger.fromHex(clientEphemeral.public)
  const B = SRPInteger.fromHex(serverPublicEphemeral)
  const s = SRPInteger.fromHex(salt)
  const p = String(password)
  const I = String(username)

  // B % N > 0
  if (B.mod(N).equals(SRPInteger.ZERO)) {
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
    key: K.toHex(),
    proof: M.toHex()
  }
}

exports.verifySession = function (clientEphemeral, clientSession, serverSessionProof) {
  // H()  One-way hash function
  const { H } = params

  // A    Public ephemeral values
  // M    Proof of K
  // K    Shared, strong session key
  const A = SRPInteger.fromHex(clientEphemeral.public)
  const M = SRPInteger.fromHex(clientSession.proof)
  const K = SRPInteger.fromHex(clientSession.key)

  // H(A, M, K)
  const expected = H(A, M, K)
  const actual = SRPInteger.fromHex(serverSessionProof)

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('Server provided session proof is invalid')
  }
}
