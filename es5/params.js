"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashOutputBytes = exports.H = exports.k = exports.g = exports.N = void 0;
var sha256_1 = __importDefault(require("./sha256"));
var srp_integer_1 = __importDefault(require("./srp-integer"));
var input = {
    largeSafePrime: "\n    AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294\n    3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D\n    CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB\n    D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74\n    7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A\n    436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D\n    5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73\n    03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6\n    94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F\n    9E4AFF73\n  ",
    generatorModulo: '02',
    hashFunction: 'sha256',
    hashOutputBytes: 256 / 8,
};
// N    A large safe prime (N = 2q+1, where q is prime)
// g    A generator modulo N
// k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
// H()  One-way hash function
exports.N = srp_integer_1.default.fromHex(input.largeSafePrime.replace(/\s+/g, ''));
exports.g = srp_integer_1.default.fromHex(input.generatorModulo.replace(/\s+/g, ''));
exports.k = sha256_1.default(exports.N, exports.g);
exports.H = sha256_1.default;
exports.hashOutputBytes = input.hashOutputBytes;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicGFyYW1zLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL3BhcmFtcy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxvREFBNkI7QUFDN0IsOERBQXNDO0FBRXRDLElBQU0sS0FBSyxHQUFHO0lBQ2IsY0FBYyxFQUFFLHduQkFXZDtJQUNGLGVBQWUsRUFBRSxJQUFJO0lBQ3JCLFlBQVksRUFBRSxRQUFRO0lBQ3RCLGVBQWUsRUFBRSxHQUFHLEdBQUcsQ0FBQztDQUN4QixDQUFBO0FBRUQsdURBQXVEO0FBQ3ZELDRCQUE0QjtBQUM1Qiw0RUFBNEU7QUFDNUUsNkJBQTZCO0FBQ2hCLFFBQUEsQ0FBQyxHQUFHLHFCQUFVLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxjQUFjLENBQUMsT0FBTyxDQUFDLE1BQU0sRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFBO0FBQ2hFLFFBQUEsQ0FBQyxHQUFHLHFCQUFVLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxlQUFlLENBQUMsT0FBTyxDQUFDLE1BQU0sRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFBO0FBQ2pFLFFBQUEsQ0FBQyxHQUFHLGdCQUFNLENBQUMsT0FBTyxDQUFDLENBQUMsRUFBRSxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUE7QUFDaEMsUUFBQSxDQUFDLEdBQUcsZ0JBQU0sQ0FBQTtBQUVWLFFBQUEsZUFBZSxHQUFHLEtBQUssQ0FBQyxlQUFlLENBQUEifQ==