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
export function deriveSession(clientSecretEphemeral: string, serverPublicEphemeral: string, salt: string, username: string, password: string): Session
export function verifySession(clientPublicEphemeral: string, clientSession: Session, proof: string): void
