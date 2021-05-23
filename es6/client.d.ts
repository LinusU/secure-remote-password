export declare const generateSalt: () => string;
export declare const derivePrivateKey: (salt: string, username: string, password: string) => string;
export declare const deriveVerifier: (privateKey: string) => string;
export declare const generateEphemeral: () => {
    secret: string;
    public: string;
};
export declare const deriveSession: (clientSecretEphemeral: string, serverPublicEphemeral: string, salt: string, username: string, privateKey: string) => {
    key: string;
    proof: string;
};
export declare const verifySession: (clientPublicEphemeral: string, clientSession: {
    proof: string;
    key: string;
}, serverSessionProof: string) => void;
