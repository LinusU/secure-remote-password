import arrayBufferToHex from 'array-buffer-to-hex';
import encodeUtf8 from 'encode-utf8';
import hexToArrayBuffer from 'hex-to-array-buffer';
import rawSha256 from 'crypto-digest-sync/sha256';
import SRPInteger from './srp-integer';
function concat(buffers) {
    const length = buffers.reduce((mem, item) => mem + item.byteLength, 0);
    const combined = new Uint8Array(length);
    buffers.reduce((offset, item) => {
        combined.set(new Uint8Array(item), offset);
        return offset + item.byteLength;
    }, 0);
    return combined.buffer;
}
const sha256 = (...args) => {
    const buffer = concat(args.map((arg) => {
        if (arg instanceof SRPInteger) {
            return hexToArrayBuffer(arg.toHex());
        }
        else if (typeof arg === 'string') {
            return encodeUtf8(arg);
        }
        else {
            throw new TypeError('Expected string or SRPInteger');
        }
    }));
    return SRPInteger.fromHex(arrayBufferToHex(rawSha256(buffer)));
};
export default sha256;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2hhMjU2LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL3NoYTI1Ni50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLGdCQUFnQixNQUFNLHFCQUFxQixDQUFBO0FBQ2xELE9BQU8sVUFBVSxNQUFNLGFBQWEsQ0FBQTtBQUNwQyxPQUFPLGdCQUFnQixNQUFNLHFCQUFxQixDQUFBO0FBQ2xELE9BQU8sU0FBUyxNQUFNLDJCQUEyQixDQUFBO0FBQ2pELE9BQU8sVUFBVSxNQUFNLGVBQWUsQ0FBQTtBQUV0QyxTQUFTLE1BQU0sQ0FBQyxPQUFzQjtJQUNyQyxNQUFNLE1BQU0sR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLElBQUksRUFBRSxFQUFFLENBQUMsR0FBRyxHQUFHLElBQUksQ0FBQyxVQUFVLEVBQUUsQ0FBQyxDQUFDLENBQUE7SUFDdEUsTUFBTSxRQUFRLEdBQUcsSUFBSSxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUE7SUFFdkMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLE1BQU0sRUFBRSxJQUFJLEVBQUUsRUFBRTtRQUMvQixRQUFRLENBQUMsR0FBRyxDQUFDLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFBO1FBQzFDLE9BQU8sTUFBTSxHQUFHLElBQUksQ0FBQyxVQUFVLENBQUE7SUFDaEMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFBO0lBRUwsT0FBTyxRQUFRLENBQUMsTUFBTSxDQUFBO0FBQ3ZCLENBQUM7QUFFRCxNQUFNLE1BQU0sR0FBRyxDQUFDLEdBQUcsSUFBa0IsRUFBRSxFQUFFO0lBQ3hDLE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FDcEIsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQWUsRUFBRSxFQUFFO1FBQzVCLElBQUksR0FBRyxZQUFZLFVBQVUsRUFBRTtZQUM5QixPQUFPLGdCQUFnQixDQUFDLEdBQUcsQ0FBQyxLQUFLLEVBQUUsQ0FBQyxDQUFBO1NBQ3BDO2FBQU0sSUFBSSxPQUFPLEdBQUcsS0FBSyxRQUFRLEVBQUU7WUFDbkMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUE7U0FDdEI7YUFBTTtZQUNOLE1BQU0sSUFBSSxTQUFTLENBQUMsK0JBQStCLENBQUMsQ0FBQTtTQUNwRDtJQUNGLENBQUMsQ0FBQyxDQUNGLENBQUE7SUFFRCxPQUFPLFVBQVUsQ0FBQyxPQUFPLENBQUMsZ0JBQWdCLENBQUMsU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQTtBQUMvRCxDQUFDLENBQUE7QUFFRCxlQUFlLE1BQU0sQ0FBQSJ9