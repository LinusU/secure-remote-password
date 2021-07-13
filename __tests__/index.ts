import client from "../client";
import SRPInteger from "../lib/srp-integer";
import server from "../server";

describe("Secure Remote Password", () => {
  it("should authenticate a user", () => {
    const username = "linus@folkdatorn.se";
    const password = "$uper$ecure";

    const salt = client.generateSalt();
    const privateKey = client.derivePrivateKey(salt, username, password);
    const verifier = client.deriveVerifier(privateKey);

    const clientEphemeral = client.generateEphemeral();
    const serverEphemeral = server.generateEphemeral(verifier);

    const clientSession = client.deriveSession(
      clientEphemeral.secret,
      serverEphemeral.public,
      salt,
      username,
      privateKey,
    );
    const serverSession = server.deriveSession(
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
});

describe("SRPInteger", () => {
  it("should keep padding when going back and forth", () => {
    expect(SRPInteger.fromHex("a").toHex()).toStrictEqual("a");
    expect(SRPInteger.fromHex("0a").toHex()).toStrictEqual("0a");
    expect(SRPInteger.fromHex("00a").toHex()).toStrictEqual("00a");
    expect(SRPInteger.fromHex("000a").toHex()).toStrictEqual("000a");
    expect(SRPInteger.fromHex("0000a").toHex()).toStrictEqual("0000a");
    expect(SRPInteger.fromHex("00000a").toHex()).toStrictEqual("00000a");
    expect(SRPInteger.fromHex("000000a").toHex()).toStrictEqual("000000a");
    expect(SRPInteger.fromHex("0000000a").toHex()).toStrictEqual("0000000a");
    expect(SRPInteger.fromHex("00000000a").toHex()).toStrictEqual("00000000a");
  });
});
