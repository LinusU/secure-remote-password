import arrayBufferToHex from 'array-buffer-to-hex'
import encodeUtf8 from 'encode-utf8'
import hexToArrayBuffer from 'hex-to-array-buffer'
import rawSha256 from 'crypto-digest-sync/sha256'

import SRPInteger from './srp-integer'

function concat(buffers: ArrayBuffer[]) {
	const length = buffers.reduce((mem, item) => mem + item.byteLength, 0)
	const combined = new Uint8Array(length)

	buffers.reduce((offset, item) => {
		combined.set(new Uint8Array(item), offset)
		return offset + item.byteLength
	}, 0)

	return combined.buffer
}

const sha256 = (...args: SRPInteger[]) => {
	const buffer = concat(
		args.map((arg: SRPInteger) => {
			if (arg instanceof SRPInteger) {
				return hexToArrayBuffer(arg.toHex())
			} else if (typeof arg === 'string') {
				return encodeUtf8(arg)
			} else {
				throw new TypeError('Expected string or SRPInteger')
			}
		})
	)

	return SRPInteger.fromHex(arrayBufferToHex(rawSha256(buffer)))
}

export default sha256
