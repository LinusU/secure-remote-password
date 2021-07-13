const textEncoder = new TextEncoder();

export const encodeUtf8 = (input: string): Uint8Array =>
  textEncoder.encode(input);
