export interface Ephemeral {
  public: string
  secret: string
}

export interface Session {
  key: string
  proof: string
}

export function generateSalt(): string
export function derivePrivateKey(salt: string, username: string, password: string): string
export function deriveVerifier(privateKey: string): string
export function generateEphemeral(): Ephemeral
export function deriveSession(clientEphemeral: Ephemeral, serverPublicEphemeral: string, salt: string, username: string, password: string): Session
export function verifySession(clientEphemeral: Ephemeral, clientSession: Session, proof: string): void
