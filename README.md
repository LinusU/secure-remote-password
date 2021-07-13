# Secure Remote Password for JavaScript

A modern [SRP](http://srp.stanford.edu) implementation for modern Node.js (v15+) and web browsers.

## Installation

```sh
yarn add @zoontek/secure-remote-password
```

## Usage

### Signing up

When creating an account with the server, the client will provide a salt and a verifier for the server to store. They are calculated by the client as follows:

```ts
import * as client from "@zoontek/secure-remote-password/client";

// These should come from the user signing up
const username = "linus@folkdatorn.se";
const password = "$uper$ecure";

const salt = client.generateSalt();
const privateKey = await client.derivePrivateKey(salt, username, password);
const verifier = client.deriveVerifier(privateKey);

console.log(salt);
//=> FB95867E...

console.log(verifier);
//=> 9392093F...

// Send `username`, `salt` and `verifier` to the server
```

_note:_ `derivePrivateKey` is provided for completeness with the SRP 6a specification. It is however recommended to use some form of "slow hashing", like [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2), to reduce the viability of a brute force attack against the verifier.

_note:_ The use of a username as part of the verifier calculation means that if the user changes their username they must simultaneously provide an update salt and verifier to the server. If a user is able to login with multiple identifiers (e.g. username, phone number, or email address) you would need a separate verifier for each identifier. To avoid these issues you can leave the `username` blank for purposes of this algorithm. The downside of not using a username is that a server can do an attack to determine whether two users have the same password. For normal apps that trust the server but use SRP just to avoid transmitting plaintext passwords, this may be an acceptable trade-off.

### Logging in

Authenticating with the server involves multiple steps.

**1** - The client generates a secret/public ephemeral value pair.

```ts
import * as client from "@zoontek/secure-remote-password/client";

// This should come from the user logging in
const username = "linus@folkdatorn.se";

const clientEphemeral = client.generateEphemeral();

console.log(clientEphemeral.public);
//=> DE63C51E...

// Send `username` and `clientEphemeral.public` to the server
```

**2** - The server receives the client's public ephemeral value and username. Using the username we retrieve the `salt` and `verifier` from our user database. We then generate our own ephemeral value pair.

_note:_ if no user cannot be found in the database, a bogus salt and ephemeral value should be returned, to avoid leaking which users have signed up

```ts
import * as server from "@zoontek/secure-remote-password/server";

// This should come from the user database
const salt = "FB95867E...";
const verifier = "9392093F...";

const serverEphemeral = await server.generateEphemeral(verifier);

console.log(serverEphemeral.public);
//=> DA084F5C...

// Store `serverEphemeral.secret` for later use
// Send `salt` and `serverEphemeral.public` to the client
```

**3** - The client can now derive the shared strong session key, and a proof of it to provide to the server.

```ts
import * as client from "@zoontek/secure-remote-password/client";

// This should come from the user logging in
const password = "$uper$ecret";
const privateKey = await client.derivePrivateKey(salt, username, password);

const clientSession = await client.deriveSession(
  clientEphemeral.secret,
  serverPublicEphemeral,
  salt,
  username,
  privateKey,
);

console.log(clientSession.key);
//=> 2A6FF04E...

console.log(clientSession.proof);
//=> 6F8F4AC3

// Send `clientSession.proof` to the server
```

**4** - The server is also ready to derive the shared strong session key, and can verify that the client has the same key using the provided proof.

```ts
import * as server from "@zoontek/secure-remote-password/server";

// Previously stored `serverEphemeral.secret`
const serverSecretEphemeral = "784D6E83...";

const serverSession = await server.deriveSession(
  serverSecretEphemeral,
  clientPublicEphemeral,
  salt,
  username,
  verifier,
  clientSessionProof,
);

console.log(serverSession.key);
//=> 2A6FF04E...

console.log(serverSession.proof);
//=> 92561B95

// Send `serverSession.proof` to the client
```

**5** - Finally, the client can verify that the server have derived the correct strong session key, using the proof that the server sent back.

```ts
import client from "@zoontek/secure-remote-password/client";

await client.verifySession(
  clientEphemeral.public,
  clientSession,
  serverSessionProof,
);

// All done!
```

## API

```ts
import {
  derivePrivateKey,
  deriveSession,
  deriveVerifier,
  generateEphemeral,
  generateSalt,
  verifySession,
} from "@zoontek/secure-remote-password/client";
```

```ts
type generateSalt = () => string;
```

Generate a salt suitable for computing the verifier with.

```ts
type derivePrivateKey = (
  salt: string,
  username: string,
  password: string,
) => Promise<string>;
```

Derives a private key suitable for computing the verifier with.

```ts
type deriveVerifier = (privateKey: string) => string;
```

Derive a verifier to be stored for subsequent authentication attempts.

```ts
type generateEphemeral = () => Ephemeral;
```

Generate ephemeral values used to initiate an authentication session.

```ts
type deriveSession = (
  clientSecretEphemeral: string,
  serverPublicEphemeral: string,
  salt: string,
  username: string,
  privateKey: string,
) => Promise<Session>;
```

Compute a session key and proof. The proof is to be sent to the server for verification.

```ts
type verifySession = (
  clientPublicEphemeral: string,
  clientSession: Session,
  serverSessionProof: string,
) => Promise<void>;
```

Verifies the server provided session proof. Throws an error if the session proof is invalid.

```ts
import {
  deriveSession,
  generateEphemeral,
} from "@zoontek/secure-remote-password/server";
```

```ts
type generateEphemeral = (verifier: string) => Promise<Ephemeral>;
```

Generate ephemeral values used to continue an authentication session.

```ts
type deriveSession = (
  serverSecretEphemeral: string,
  clientPublicEphemeral: string,
  salt: string,
  username: string,
  verifier: string,
  clientSessionProof: string,
) => Promise<Session>;
```

Compute a session key and proof. The proof is to be sent to the client for verification.

Throws an error if the session proof from the client is invalid.
