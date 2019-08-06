/* eslint-env mocha */

const assert = require('assert')

const client = require('./client')
const server = require('./server')
const SRPInteger = require('./lib/srp-integer')
const params = require('./lib/params')

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

describe('SRP Test Vectors', () => {
  it('should match known test vector', () => {
    const testVector = {
      'H': 'sha256',
      'size': 2048,
      'N': 'ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73',
      'g': '02',
      'I': 'alice',
      'P': 'password123',
      's': 'beb25379d1a8581eb5a727673a2441ee',
      'k': '05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300',
      'x': '0065ac38dff8bc34ae0f259e91fbd0f4ca2fa43081c9050cec7cac20d015f303',
      'v': '400272a61e185e23784e28a16a149dc60a3790fd45856f79a7070c44f7da1ca22f711cd5bc3592171a875c7812472916de2dcfafc22f7dead8f578f1970547936f9eec686bb3df66ff57f724f6b907e83530812b4ffdbf614153e9fbfed4fc6d972da70bb23f6ccd36ad08b72567fe6bcd2bacb713f2cdb9dc8f81f897f489bb393067d66237a3e061902e72096d5ac1cd1d06c1cd648f7e56da5ec6e0094c1b448c5d63ad2addec1e3d9a3aa7118a0410e53434ddbffc60eef5b82548bda5a2f513209484d3221982ca74668a4d37330cc9cfe3b10f0db368293e43026e3a01440ac732bc1cfb983b512d10296f6951ec5e567329af8e58d7c21ea6c778b0bd',
      'a': '60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393',
      'b': 'e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20',
      'A': '4b700f8d48e69c9aae40c684ac7c7c03121e2b7602eb4c3514804ccada0ed4019193a351ecc65a6f854ede91eb096e721b22d701c7adc64e9cedacd75f2e26bb2f5e45dd53dc8dbeafffe82aa49fca0573444691212537a73cf80e25039258205a7edf4749b30adaf25877c62fcd09d6613598bcd4baf2a9727a53706a278148992b2abb23ad5d512d269e16ca11bc0895b5a3b5ec4721cde40a8c39c796e94f0be86dbbeb33da7037018983921aba3f5053195d5ac1da4e567e3c0e75d9e0609f92e850657b2be4771f415b9cacc5c1ecedc30133bf6474f5022c6519d780760ca4d8d3b966b034bd73877c1b3b33f474b9c3c5299a1968f3e6cd3bfe84445a',
      'B': '410813e3063f3b4532f2d36413749f39c26c5ceeb1346d3995003c74544c30cba318f981281607ae68dbdc3bee9f0544ada6b13d8ac33217b670973152cf03ef03797615e81dd305342c2e3bb035321d1fd717952e702b09682102d0a5aa25dcee01784a32b0684f75626ca3bf8aec874f2dc11f8926944b06f9948e8ad7649025a58cd9dccdb6b210de00e2283e72baaf93a39b0417dfd1888f841f43d7d41c75b58f654ccb2e8b9c875c42edc34fd3796200312f2abd19b7e2c54b5702cd1a7f4d79fdf73bc418c96466ba122d45474ab6db553417715617f6c3b4a8764279f086acc655e396f85812c90f6f932ce0586168c5deccc9f8beb6891ad13f7caf',
      'u': 'd56e895d00cb8a9ea81f0c9967522018bca195a485cd59687ebb2a3f5ecda88b',
      'S': '30abe90d7091d4617ea8b93f0e649f7fd1ca069bca471e9daf46f5fa5c2b31f05e650da378c0280f144e893ed8137111ff91842c01ce5e3ed8714b4cb23e2b2658230c53153948663239a31b9fdb503325f3bee65f97d081ab90c9453d79c61758e622f4fa4a76b91dfbcf9ab4dac654968756f20b620b500837e297bd51b2d4fde98267703edf69674c3f0e747f910ffec303bc15e004ecaadf3782cd9d2994ed606b7530ad0dd3e9d6de7436fabea3215a13b77a7c59d7fd20ac1df350ad8b8cdcad5ded683073dc2dadeda1350e7d72619bbe652ee53813cb7f3295ada69f53ed595de4de4ea23ffa964157a42785ff6217268f5a912551ba4adb57e8773c',
      'K': '899f35b485d44d577957e87cfdd48343d97ea2e0c3e8620594e0b8da9ce5da98',
      'M1': '7b1867ca8cc93ab5a9e40a5fd504b28f757a41b5cc5ac7de7ac1078130601c42',
      'M2': '91385641bf84309d0321b32ae665d508de8dba72342030d0a5bf46a2f05a53ca'
    }

    const { N, g, k } = params
    assert.strictEqual(N.toHex(), testVector['N'])
    assert.strictEqual(g.toHex(), testVector['g'])
    assert.strictEqual(k.toHex(), testVector['k'])

    const x = client.derivePrivateKey(testVector['s'], testVector['I'], testVector['P'])
    assert.strictEqual(x, testVector['x'])

    const v = client.deriveVerifier(x)
    assert.strictEqual(v, testVector['v'])

    const clientSession = client.deriveSession(testVector['a'],
      testVector['B'],
      testVector['s'],
      testVector['I'],
      testVector['x'])
    assert.strictEqual(clientSession.key, testVector['K'])
    assert.strictEqual(clientSession.proof, testVector['M1'])

    const serverSession = server.deriveSession(testVector['b'],
      testVector['A'],
      testVector['s'],
      testVector['I'],
      testVector['v'],
      testVector['M1'])
    assert.strictEqual(serverSession.key, testVector['K'])
    assert.strictEqual(serverSession.proof, testVector['M2'])
  })
})
