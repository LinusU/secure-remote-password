export interface Ephemeral {
  public: string
  secret: string
}

export interface Session {
  key: string
  proof: string
}

export function generateEphemeral(verifier: string): Ephemeral
export function computeSession(serverEphemeral: Ephemeral, clientPublicEphemeral: string, salt: string, username: string, verifier: string, clientSessionProof: string): Session
