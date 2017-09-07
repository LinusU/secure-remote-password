/* eslint-env mocha */

const assert = require('assert')

const client = require('./client')
const server = require('./server')

describe('Secure Remote Password', () => {
  it('should authenticate a user', () => {
    const username = 'linus@folkdatorn.se'
    const password = '$uper$ecure'

    const salt = client.generateSalt()
    const verifier = client.computeVerifier(username, password, salt)

    const clientEphemeral = client.generateEphemeral()
    const serverEphemeral = server.generateEphemeral(verifier)

    const clientSession = client.computeSession(clientEphemeral, serverEphemeral.public, salt, username, password)
    const serverSession = server.computeSession(serverEphemeral, clientEphemeral.public, salt, username, verifier, clientSession.proof)

    client.verifySession(clientEphemeral, clientSession, serverSession.proof)

    assert.strictEqual(clientSession.key, serverSession.key)
  })
})
