'use strict'

const params = require('./lib/params')
const SRPInteger = require('./lib/srp-integer')

exports.generateSalt = function () {
  // s      User's salt
  const s = SRPInteger.randomInteger(params.hashOutputBytes)

  return s.toHex()
}

exports.derivePrivateKey = function (salt, username, password) {
  // H()    One-way hash function
  const { H } = params

  // s      User's salt
  // I      Username
  // p      Cleartext Password
  const s = SRPInteger.fromHex(salt)
  const I = String(username)
  const p = String(password)

  // x = H(s, H(I | ':' | p))  (s is chosen randomly)
  const x = H(s, H(`${I}:${p}`))

  return x.toHex()
}

exports.deriveVerifier = function (privateKey) {
  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  const { N, g } = params

  // x      Private key (derived from p and s)
  const x = SRPInteger.fromHex(privateKey)

  // v = g^x                   (computes password verifier)
  const v = g.modPow(x, N)

  return v.toHex()
}

exports.generateEphemeral = function () {
  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  const { N, g } = params

  // A = g^a                  (a = random number)
  const a = SRPInteger.randomInteger(params.hashOutputBytes)
  const A = g.modPow(a, N)

  return {
    secret: a.toHex(),
    public: A.toHex()
  }
}

exports.deriveSession = function (clientSecretEphemeral, serverPublicEphemeral, salt, username, privateKey) {
  // N      A large safe prime (N = 2q+1, where q is prime)
  // g      A generator modulo N
  // k      Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  // H()    One-way hash function
  // PAD()  Pad the number to have the same number of bytes as N
  const { N, g, k, H, PAD } = params

  // a      Secret ephemeral values
  // B      Public ephemeral values
  // s      User's salt
  // I      Username
  // x      Private key (derived from p and s)
  const a = SRPInteger.fromHex(clientSecretEphemeral)
  const B = SRPInteger.fromHex(serverPublicEphemeral)
  const s = SRPInteger.fromHex(salt)
  const I = String(username)
  const x = SRPInteger.fromHex(privateKey)

  // A = g^a                  (a = random number)
  const A = g.modPow(a, N)

  // B % N > 0
  if (B.mod(N).equals(SRPInteger.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error('The server sent an invalid public ephemeral')
  }

  // u = H(PAD(A), PAD(B))
  const u = H(PAD(A), PAD(B))

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

exports.verifySession = function (clientPublicEphemeral, clientSession, serverSessionProof) {
  // H()    One-way hash function
  const { H } = params

  // A      Public ephemeral values
  // M      Proof of K
  // K      Shared, strong session key
  const A = SRPInteger.fromHex(clientPublicEphemeral)
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
