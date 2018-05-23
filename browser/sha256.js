'use strict'

const arrayBufferToHex = require('array-buffer-to-hex')
const encodeUtf8 = require('encode-utf8')
const hexToArrayBuffer = require('hex-to-array-buffer')
const rawSha256 = require('crypto-digest-sync/sha256')

const SRPInteger = require('../lib/srp-integer')

function concat (buffers) {
  const length = buffers.reduce((mem, item) => mem + item.byteLength, 0)
  const combined = new Uint8Array(length)

  buffers.reduce((offset, item) => {
    combined.set(new Uint8Array(item), offset)
    return offset + item.byteLength
  }, 0)

  return combined.buffer
}

/**
 * @param {(string | SRPInteger)[]} args
 */
module.exports = function sha256 (...args) {
  const buffer = concat(args.map((arg) => {
    if (arg instanceof SRPInteger) {
      return hexToArrayBuffer(arg.toHex())
    } else if (typeof arg === 'string') {
      return encodeUtf8(arg)
    } else {
      throw new TypeError('Expected string or SRPInteger')
    }
  }))

  return SRPInteger.fromHex(arrayBufferToHex(rawSha256(buffer)))
}
