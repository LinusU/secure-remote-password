import { bufferToHex, hexToBuffer } from "./buffer";
import { crypto } from "./crypto";
import { SRPInt } from "./SRPInt";

const textEncoder = new TextEncoder();

export const sha256 = async (...input: (SRPInt | string)[]) => {
  const buffers = input.map((item) =>
    typeof item === "string"
      ? textEncoder.encode(item)
      : hexToBuffer(item.toHex()),
  );

  const combined = new Uint8Array(
    buffers.reduce((offset, item) => offset + item.byteLength, 0),
  );

  buffers.reduce((offset, item) => {
    combined.set(new Uint8Array(item), offset);
    return offset + item.byteLength;
  }, 0);

  return SRPInt.fromHex(
    bufferToHex(await crypto.subtle.digest("SHA-256", combined.buffer)),
  );
};
