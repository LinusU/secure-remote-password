export interface Ephemeral {
  public: string
  secret: string
}

export interface Session {
  key: string
  proof: string
}

export function generateSalt(): string
export function computeVerifier(username: string, password: string, salt: string): string
export function generateEphemeral(): Ephemeral
export function computeSession(clientEphemeral: Ephemeral, serverPublicEphemeral: string, salt: string, username: string, password: string): Session
export function verifySession(clientEphemeral: Ephemeral, clientSession: Session, proof: string): void
