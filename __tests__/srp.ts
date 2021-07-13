import * as client from "../src/client";
import * as server from "../src/server";
import { SRPInt } from "../src/SRPInt";

test("Secure Remote Password should authenticate a user", async () => {
  const username = "linus@folkdatorn.se";
  const password = "$uper$ecure";

  const salt = client.generateSalt();
  const privateKey = await client.derivePrivateKey(salt, username, password);
  const verifier = client.deriveVerifier(privateKey);

  const clientEphemeral = client.generateEphemeral();
  const serverEphemeral = await server.generateEphemeral(verifier);

  const clientSession = await client.deriveSession(
    clientEphemeral.secret,
    serverEphemeral.public,
    salt,
    username,
    privateKey,
  );

  const serverSession = await server.deriveSession(
    serverEphemeral.secret,
    clientEphemeral.public,
    salt,
    username,
    verifier,
    clientSession.proof,
  );

  client.verifySession(
    clientEphemeral.public,
    clientSession,
    serverSession.proof,
  );

  expect(clientSession.key).toStrictEqual(serverSession.key);
});

test("SRPInt should keep padding when going back and forth", () => {
  expect(SRPInt.fromHex("a").toHex()).toStrictEqual("a");
  expect(SRPInt.fromHex("0a").toHex()).toStrictEqual("0a");
  expect(SRPInt.fromHex("00a").toHex()).toStrictEqual("00a");
  expect(SRPInt.fromHex("000a").toHex()).toStrictEqual("000a");
  expect(SRPInt.fromHex("0000a").toHex()).toStrictEqual("0000a");
  expect(SRPInt.fromHex("00000a").toHex()).toStrictEqual("00000a");
  expect(SRPInt.fromHex("000000a").toHex()).toStrictEqual("000000a");
  expect(SRPInt.fromHex("0000000a").toHex()).toStrictEqual("0000000a");
  expect(SRPInt.fromHex("00000000a").toHex()).toStrictEqual("00000000a");
});
