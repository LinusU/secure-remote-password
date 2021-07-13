# Secure Remote Password for JavaScript

A modern [SRP](http://srp.stanford.edu) implementation for Node.js and Web Browsers.

## Installation

```sh
npm install --save secure-remote-password
```

## Usage

### Signing up

When creating an account with the server, the client will provide a salt and a verifier for the server to store. They are calculated by the client as follows:

```js
const srp = require("secure-remote-password/client");

// These should come from the user signing up
const username = "linus@folkdatorn.se";
const password = "$uper$ecure";

const salt = srp.generateSalt();
const privateKey = srp.derivePrivateKey(salt, username, password);
const verifier = srp.deriveVerifier(privateKey);

console.log(salt);
//=> FB95867E...

console.log(verifier);
//=> 9392093F...

// Send `username`, `salt` and `verifier` to the server
```

_note:_ `derivePrivateKey` is provided for completeness with the SRP 6a specification. It is however recommended to use some form of "slow hashing", like [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2), to reduce the viability of a brute force attack against the verifier.

### Logging in

Authenticating with the server involves mutliple steps.

**1** - The client generates a secret/public ephemeral value pair.

```js
const srp = require("secure-remote-password/client");

// This should come from the user logging in
const username = "linus@folkdatorn.se";

const clientEphemeral = srp.generateEphemeral();

console.log(clientEphemeral.public);
//=> DE63C51E...

// Send `username` and `clientEphemeral.public` to the server
```

**2** - The server receives the client's public ephemeral value and username. Using the username we retrieve the `salt` and `verifier` from our user database. We then generate our own ephemeral value pair.

_note:_ if no user cannot be found in the database, a bogus salt and ephemeral value should be returned, to avoid leaking which users have signed up

```js
const srp = require("secure-remote-password/server");

// This should come from the user database
const salt = "FB95867E...";
const verifier = "9392093F...";

const serverEphemeral = srp.generateEphemeral(verifier);

console.log(serverEphemeral.public);
//=> DA084F5C...

// Store `serverEphemeral.secret` for later use
// Send `salt` and `serverEphemeral.public` to the client
```

**3** - The client can now derive the shared strong session key, and a proof of it to provide to the server.

```js
const srp = require("secure-remote-password/client");

// This should come from the user logging in
const password = "$uper$ecret";

const privateKey = srp.derivePrivateKey(salt, username, password);
const clientSession = srp.deriveSession(
  clientEphemeral.secret,
  serverPublicEphemeral,
  salt,
  username,
  privateKey
);

console.log(clientSession.key);
//=> 2A6FF04E...

console.log(clientSession.proof);
//=> 6F8F4AC3

// Send `clientSession.proof` to the server
```

**4** - The server is also ready to derive the shared strong session key, and can verify that the client has the same key using the provided proof.

```js
const srp = require("secure-remote-password/server");

// Previously stored `serverEphemeral.secret`
const serverSecretEphemeral = "784D6E83...";

const serverSession = srp.deriveSession(
  serverSecretEphemeral,
  clientPublicEphemeral,
  salt,
  username,
  verifier,
  clientSessionProof
);

console.log(serverSession.key);
//=> 2A6FF04E...

console.log(serverSession.proof);
//=> 92561B95

// Send `serverSession.proof` to the client
```

**5** - Finally, the client can verify that the server have derived the correct strong session key, using the proof that the server sent back.

```js
const srp = require("secure-remote-password/client");

srp.verifySession(clientEphemeral.public, clientSession, serverSessionProof);

// All done!
```

## API

### `Client`

```js
const Client = require("secure-remote-password/client");
```

#### `Client.generateSalt() => string`

Generate a salt suitable for computing the verifier with.

#### `Client.derivePrivateKey(salt, username, password) => string`

Derives a private key suitable for computing the verifier with.

#### `Client.deriveVerifier(privateKey) => string`

Derive a verifier to be stored for subsequent authentication atempts.

#### `Client.generateEphemeral() => { secret: string, public: string }`

Generate ephemeral values used to initiate an authentication session.

#### `Client.deriveSession(clientSecretEphemeral, serverPublicEphemeral, salt, username, privateKey) => { key: string, proof: string }`

Comptue a session key and proof. The proof is to be sent to the server for verification.

#### `Client.verifySession(clientPublicEphemeral, clientSession, serverSessionProof) => void`

Verifies the server provided session proof. Throws an error if the session proof is invalid.

### `Server`

```js
const Server = require("secure-remote-password/server");
```

#### `generateEphemeral(verifier)`

Generate ephemeral values used to continue an authentication session.

#### `deriveSession(serverSecretEphemeral, clientPublicEphemeral, salt, username, verifier, clientSessionProof)`

Comptue a session key and proof. The proof is to be sent to the client for verification.

Throws an error if the session proof from the client is invalid.
