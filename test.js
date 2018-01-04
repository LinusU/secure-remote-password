/* eslint-env mocha */

const assert = require('assert')

const client = require('./client')
const server = require('./server')
const SRPInteger = require('./lib/srp-integer')

describe('Secure Remote Password', () => {
  it('should authenticate a user', () => {
    const username = 'linus@folkdatorn.se'
    const password = '$uper$ecure'

    const salt = client.generateSalt()
    const privateKey = client.derivePrivateKey(salt, username, password)
    const verifier = client.deriveVerifier(privateKey)

    const clientEphemeral = client.generateEphemeral()
    const serverEphemeral = server.generateEphemeral(verifier)

    const clientSession = client.deriveSession(clientEphemeral.secret, serverEphemeral.public, salt, username, privateKey)
    const serverSession = server.deriveSession(serverEphemeral.secret, clientEphemeral.public, salt, username, verifier, clientSession.proof)

    client.verifySession(clientEphemeral.public, clientSession, serverSession.proof)

    assert.strictEqual(clientSession.key, serverSession.key)
  })
})

describe('SRPInteger', () => {
  it('should keep padding when going back and forth', () => {
    assert.strictEqual(SRPInteger.fromHex('a').toHex(), 'a')
    assert.strictEqual(SRPInteger.fromHex('0a').toHex(), '0a')
    assert.strictEqual(SRPInteger.fromHex('00a').toHex(), '00a')
    assert.strictEqual(SRPInteger.fromHex('000a').toHex(), '000a')
    assert.strictEqual(SRPInteger.fromHex('0000a').toHex(), '0000a')
    assert.strictEqual(SRPInteger.fromHex('00000a').toHex(), '00000a')
    assert.strictEqual(SRPInteger.fromHex('000000a').toHex(), '000000a')
    assert.strictEqual(SRPInteger.fromHex('0000000a').toHex(), '0000000a')
    assert.strictEqual(SRPInteger.fromHex('00000000a').toHex(), '00000000a')
  })
})
