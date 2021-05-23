"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_random_hex_1 = __importDefault(require("crypto-random-hex"));
var jsbn_1 = require("jsbn");
var padStart = function (str, maxLength, fillString) {
    return str.padStart(maxLength, fillString);
};
var kBigInteger = Symbol('big-integer');
var kHexLength = Symbol('hex-length');
var SRPInteger = /** @class */ (function () {
    function SRPInteger(bigInteger, hexLength) {
        this[kBigInteger] = bigInteger;
        this[kHexLength] = hexLength;
    }
    SRPInteger.prototype.add = function (val) {
        return new SRPInteger(this[kBigInteger].add(val[kBigInteger]), null);
    };
    SRPInteger.prototype.equals = function (val) {
        return this[kBigInteger].equals(val[kBigInteger]);
    };
    SRPInteger.prototype.multiply = function (val) {
        return new SRPInteger(this[kBigInteger].multiply(val[kBigInteger]), null);
    };
    SRPInteger.prototype.modPow = function (exponent, m) {
        return new SRPInteger(this[kBigInteger].modPow(exponent[kBigInteger], m[kBigInteger]), m[kHexLength]);
    };
    SRPInteger.prototype.mod = function (m) {
        return new SRPInteger(this[kBigInteger].mod(m[kBigInteger]), m[kHexLength]);
    };
    SRPInteger.prototype.subtract = function (val) {
        return new SRPInteger(this[kBigInteger].subtract(val[kBigInteger]), this[kHexLength]);
    };
    SRPInteger.prototype.xor = function (val) {
        return new SRPInteger(this[kBigInteger].xor(val[kBigInteger]), this[kHexLength]);
    };
    SRPInteger.prototype.inspect = function () {
        var hex = this[kBigInteger].toString(16);
        return "<SRPInteger " + hex.slice(0, 16) + (hex.length > 16 ? '...' : '') + ">";
    };
    SRPInteger.prototype.toHex = function () {
        var _a;
        if (this[kHexLength] === null) {
            throw new Error('This SRPInteger has no specified length');
        }
        return padStart(this[kBigInteger].toString(16), (_a = this[kHexLength]) !== null && _a !== void 0 ? _a : 0, '0');
    };
    return SRPInteger;
}());
SRPInteger.fromHex = function (input) {
    return new SRPInteger(new jsbn_1.BigInteger(input, 16), input.length);
};
SRPInteger.randomInteger = function (bytes) {
    return SRPInteger.fromHex(crypto_random_hex_1.default(bytes));
};
SRPInteger.ZERO = new SRPInteger(new jsbn_1.BigInteger('0'), null);
exports.default = SRPInteger;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic3JwLWludGVnZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvc3JwLWludGVnZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSx3RUFBeUM7QUFDekMsNkJBQWlDO0FBRWpDLElBQU0sUUFBUSxHQUFHLFVBQUMsR0FBVyxFQUFFLFNBQWlCLEVBQUUsVUFBa0I7SUFDbkUsT0FBQSxHQUFHLENBQUMsUUFBUSxDQUFDLFNBQVMsRUFBRSxVQUFVLENBQUM7QUFBbkMsQ0FBbUMsQ0FBQTtBQUVwQyxJQUFNLFdBQVcsR0FBRyxNQUFNLENBQUMsYUFBYSxDQUFDLENBQUE7QUFDekMsSUFBTSxVQUFVLEdBQUcsTUFBTSxDQUFDLFlBQVksQ0FBQyxDQUFBO0FBRXZDO0lBT0Msb0JBQVksVUFBc0IsRUFBRSxTQUF3QjtRQUMzRCxJQUFJLENBQUMsV0FBVyxDQUFDLEdBQUcsVUFBVSxDQUFBO1FBQzlCLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxTQUFTLENBQUE7SUFDN0IsQ0FBQztJQUVELHdCQUFHLEdBQUgsVUFBSSxHQUFlO1FBQ2xCLE9BQU8sSUFBSSxVQUFVLENBQUMsSUFBSSxDQUFDLFdBQVcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsV0FBVyxDQUFDLENBQUMsRUFBRSxJQUFJLENBQUMsQ0FBQTtJQUNyRSxDQUFDO0lBRUQsMkJBQU0sR0FBTixVQUFPLEdBQWU7UUFDckIsT0FBTyxJQUFJLENBQUMsV0FBVyxDQUFDLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFBO0lBQ2xELENBQUM7SUFFRCw2QkFBUSxHQUFSLFVBQVMsR0FBZTtRQUN2QixPQUFPLElBQUksVUFBVSxDQUNwQixJQUFJLENBQUMsV0FBVyxDQUFDLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxXQUFXLENBQUMsQ0FBQyxFQUM1QyxJQUFJLENBQ0osQ0FBQTtJQUNGLENBQUM7SUFFRCwyQkFBTSxHQUFOLFVB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