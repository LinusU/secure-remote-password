export declare const generateEphemeral: (verifier: string) => {
    secret: string;
    public: string;
};
export declare const deriveSession: (serverSecretEphemeral: string, clientPublicEphemeral: string, salt: string, username: string, verifier: string, clientSessionProof: string) => {
    key: string;
    proof: string;
};
