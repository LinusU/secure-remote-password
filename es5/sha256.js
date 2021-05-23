"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var array_buffer_to_hex_1 = __importDefault(require("array-buffer-to-hex"));
var encode_utf8_1 = __importDefault(require("encode-utf8"));
var hex_to_array_buffer_1 = __importDefault(require("hex-to-array-buffer"));
var sha256_1 = __importDefault(require("crypto-digest-sync/sha256"));
var srp_integer_1 = __importDefault(require("./srp-integer"));
function concat(buffers) {
    var length = buffers.reduce(function (mem, item) { return mem + item.byteLength; }, 0);
    var combined = new Uint8Array(length);
    buffers.reduce(function (offset, item) {
        combined.set(new Uint8Array(item), offset);
        return offset + item.byteLength;
    }, 0);
    return combined.buffer;
}
var sha256 = function () {
    var args = [];
    for (var _i = 0; _i < arguments.length; _i++) {
        args[_i] = arguments[_i];
    }
    var buffer = concat(args.map(function (arg) {
        if (arg instanceof srp_integer_1.default) {
            return hex_to_array_buffer_1.default(arg.toHex());
        }
        else if (typeof arg === 'string') {
            return encode_utf8_1.default(arg);
        }
        else {
            throw new TypeError('Expected string or SRPInteger');
        }
    }));
    return srp_integer_1.default.fromHex(array_buffer_to_hex_1.default(sha256_1.default(buffer)));
};
exports.default = sha256;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2hhMjU2LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL3NoYTI1Ni50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLDRFQUFrRDtBQUNsRCw0REFBb0M7QUFDcEMsNEVBQWtEO0FBQ2xELHFFQUFpRDtBQUVqRCw4REFBc0M7QUFFdEMsU0FBUyxNQUFNLENBQUMsT0FBc0I7SUFDckMsSUFBTSxNQUFNLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyxVQUFDLEdBQUcsRUFBRSxJQUFJLElBQUssT0FBQSxHQUFHLEdBQUcsSUFBSSxDQUFDLFVBQVUsRUFBckIsQ0FBcUIsRUFBRSxDQUFDLENBQUMsQ0FBQTtJQUN0RSxJQUFNLFFBQVEsR0FBRyxJQUFJLFVBQVUsQ0FBQyxNQUFNLENBQUMsQ0FBQTtJQUV2QyxPQUFPLENBQUMsTUFBTSxDQUFDLFVBQUMsTUFBTSxFQUFFLElBQUk7UUFDM0IsUUFBUSxDQUFDLEdBQUcsQ0FBQyxJQUFJLFVBQVUsQ0FBQyxJQUFJLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQTtRQUMxQyxPQUFPLE1BQU0sR0FBRyxJQUFJLENBQUMsVUFBVSxDQUFBO0lBQ2hDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQTtJQUVMLE9BQU8sUUFBUSxDQUFDLE1BQU0sQ0FBQTtBQUN2QixDQUFDO0FBRUQsSUFBTSxNQUFNLEdBQUc7SUFBQyxjQUFxQjtTQUFyQixVQUFxQixFQUFyQixxQkFBcUIsRUFBckIsSUFBcUI7UUFBckIseUJBQXFCOztJQUNwQyxJQUFNLE1BQU0sR0FBRyxNQUFNLENBQ3BCLElBQUksQ0FBQyxHQUFHLENBQUMsVUFBQyxHQUFlO1FBQ3hCLElBQUksR0FBRyxZQUFZLHFCQUFVLEVBQUU7WUFDOUIsT0FBTyw2QkFBZ0IsQ0FBQyxHQUFHLENBQUMsS0FBSyxFQUFFLENBQUMsQ0FBQTtTQUNwQzthQUFNLElBQUksT0FBTyxHQUFHLEtBQUssUUFBUSxFQUFFO1lBQ25DLE9BQU8scUJBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQTtTQUN0QjthQUFNO1lBQ04sTUFBTSxJQUFJLFNBQVMsQ0FBQywrQkFBK0IsQ0FBQyxDQUFBO1NBQ3BEO0lBQ0YsQ0FBQyxDQUFDLENBQ0YsQ0FBQTtJQUVELE9BQU8scUJBQVUsQ0FBQyxPQUFPLENBQUMsNkJBQWdCLENBQUMsZ0JBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDL0QsQ0FBQyxDQUFBO0FBRUQsa0JBQWUsTUFBTSxDQUFBIn0=