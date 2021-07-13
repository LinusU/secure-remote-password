// https://github.com/LinusU/array-buffer-to-hex
// https://github.com/LinusU/hex-to-array-buffer
// https://github.com/wbinnssmith/arraybuffer-equal

export const bufferEqual = (
  bufferA: ArrayBufferLike,
  bufferB: ArrayBufferLike,
): boolean => {
  if (bufferA === bufferB) {
    return true;
  }
  if (bufferA.byteLength !== bufferB.byteLength) {
    return false;
  }

  let viewA = new DataView(bufferA);
  let viewB = new DataView(bufferB);

  let i = bufferA.byteLength;

  while (i--) {
    if (viewA.getUint8(i) !== viewB.getUint8(i)) {
      return false;
    }
  }

  return true;
};

export const bufferToHex = (buffer: ArrayBufferLike): string => {
  const view = new Uint8Array(buffer);
  let result = "";

  for (let i = 0; i < view.length; i++) {
    const item = view[i];

    if (item != null) {
      const value = item.toString(16);
      result += value.length === 1 ? "0" + value : value;
    }
  }

  return result;
};

export const hexToBuffer = (hex: string): ArrayBufferLike => {
  if (hex.length % 2 !== 0) {
    throw new RangeError("Expected string to be an even number of characters");
  }

  const view = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return view.buffer;
};
