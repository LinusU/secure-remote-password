export const crypto: Crypto =
  typeof window !== "undefined" ? window.crypto : require("crypto").webcrypto;
