import { params } from "./params";
import { SRPInt } from "./SRPInt";
import { Ephemeral, Session } from "./types";

export * from "./types";

export const generateSalt = (): string => {
  const s = SRPInt.randomInteger(params.hashOutputBytes); // User's salt
  return s.toHex();
};

export const derivePrivateKey = async (
  salt: string,
  username: string,
  password: string,
): Promise<string> => {
  const { H } = params;

  const s = SRPInt.fromHex(salt); // User's salt
  const I = String(username); // Username
  const p = String(password); // Cleartext Password

  // x = H(s, H(I | ':' | p))
  const x = await H(s, await H(`${I}:${p}`));
  return x.toHex();
};

export const deriveVerifier = (privateKey: string): string => {
  const { N, g } = params;

  const x = SRPInt.fromHex(privateKey); // Private key (derived from p and s)
  const v = g.modPow(x, N); // v = g^x (computes password verifier)
  return v.toHex();
};

export const generateEphemeral = (): Ephemeral => {
  const { N, g } = params;

  const a = SRPInt.randomInteger(params.hashOutputBytes);
  const A = g.modPow(a, N); // A = g^a

  return {
    secret: a.toHex(),
    public: A.toHex(),
  };
};

export const deriveSession = async (
  clientSecretEphemeral: string,
  serverPublicEphemeral: string,
  salt: string,
  username: string,
  privateKey: string,
): Promise<Session> => {
  const { N, g, k, H } = params;

  const a = SRPInt.fromHex(clientSecretEphemeral); // Secret ephemeral values
  const B = SRPInt.fromHex(serverPublicEphemeral); // Public ephemeral values
  const s = SRPInt.fromHex(salt); // User's salt
  const I = username; // Username
  const x = SRPInt.fromHex(privateKey); // Private key (derived from p and s)

  const A = g.modPow(a, N); // A = g^a

  // B % N > 0
  if (B.mod(N).equals(SRPInt.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The server sent an invalid public ephemeral");
  }

  const [k1, u] = await Promise.all([k, H(A, B)]);

  // S = (B - kg^x) ^ (a + ux)
  const S = B.subtract(k1.multiply(g.modPow(x, N))).modPow(
    a.add(u.multiply(x)),
    N,
  );

  const [K, HN, Hg, HI] = await Promise.all([H(S), H(N), H(g), H(I)]);
  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = await H(HN.xor(Hg), HI, s, A, B, K);

  return {
    key: K.toHex(),
    proof: M.toHex(),
  };
};

export const verifySession = async (
  clientPublicEphemeral: string,
  clientSession: Session,
  serverSessionProof: string,
): Promise<void> => {
  const { H } = params;

  const A = SRPInt.fromHex(clientPublicEphemeral); // Public ephemeral values
  const M = SRPInt.fromHex(clientSession.proof); // Proof of K
  const K = SRPInt.fromHex(clientSession.key); // Shared, strong session key

  const expected = await H(A, M, K);
  const actual = SRPInt.fromHex(serverSessionProof);

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Server provided session proof is invalid");
  }
};
