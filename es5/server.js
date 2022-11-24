"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveSession = exports.generateEphemeral = void 0;
var params = __importStar(require("./params"));
var srp_integer_1 = __importDefault(require("./srp-integer"));
var generateEphemeral = function (verifier) {
    // N    A large safe prime (N = 2q+1, where q is prime)
    // g    A generator modulo N
    // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
    var N = params.N, g = params.g, k = params.k;
    // v    Password verifier
    var v = srp_integer_1.default.fromHex(verifier);
    // B = kv + g^b             (b = random number)
    var b = srp_integer_1.default.randomInteger(params.hashOutputBytes);
    var B = k.multiply(v).add(g.modPow(b, N)).mod(N);
    return {
        secret: b.toHex(),
        public: B.toHex(),
    };
};
exports.generateEphemeral = generateEphemeral;
var deriveSession = function (serverSecretEphemeral, clientPublicEphemeral, salt, username, verifier, clientSessionProof) {
    // N    A large safe prime (N = 2q+1, where q is prime)
    // g    A generator modulo N
    // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
    // H()  One-way hash function
    var N = params.N, g = params.g, k = params.k, H = params.H;
    // b    Secret ephemeral values
    // A    Public ephemeral values
    // s    User's salt
    // p    Cleartext Password
    // I    Username
    // v    Password verifier
    var b = srp_integer_1.default.fromHex(serverSecretEphemeral);
    var A = srp_integer_1.default.fromHex(clientPublicEphemeral);
    var s = srp_integer_1.default.fromHex(salt);
    var I = String(username);
    var v = srp_integer_1.default.fromHex(verifier);
    // B = kv + g^b             (b = random number)
    var B = k.multiply(v).add(g.modPow(b, N)).mod(N);
    // A % N > 0
    if (A.mod(N).equals(srp_integer_1.default.ZERO)) {
        // fixme: .code, .statusCode, etc.
        throw new Error('The client sent an invalid public ephemeral');
    }
    // u = H(A, B)
    var u = H(A, B);
    // S = (Av^u) ^ b              (computes session key)
    var S = A.multiply(v.modPow(u, N)).modPow(b, N);
    // K = H(S)
    var K = H(S);
    // M = H(H(N) xor H(g), H(I), s, A, B, K)
    var M = H(H(N).xor(H(g)), H(srp_integer_1.default.fromHex(I)), s, A, B, K);
    var expected = M;
    var actual = srp_integer_1.default.fromHex(clientSessionProof);
    if (!actual.equals(expected)) {
        // fixme: .code, .statusCode, etc.
        throw new Error('Client provided session proof is invalid');
    }
    // P = H(A, M, K)
    var P = H(A, M, K);
    return {
        key: K.toHex(),
        proof: P.toHex(),
    };
};
exports.deriveSession = deriveSession;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2VydmVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL3NlcnZlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQ0EsK0NBQWtDO0FBQ2xDLDhEQUFzQztBQUUvQixJQUFNLGlCQUFpQixHQUFHLFVBQUMsUUFBZ0I7SUFDakQsdURBQXVEO0lBQ3ZELDRCQUE0QjtJQUM1Qiw0RUFBNEU7SUFDcEUsSUFBQSxDQUFDLEdBQVcsTUFBTSxFQUFqQixFQUFFLENBQUMsR0FBUSxNQUFNLEVBQWQsRUFBRSxDQUFDLEdBQUssTUFBTSxFQUFYLENBQVc7SUFFMUIseUJBQXlCO0lBQ3pCLElBQU0sQ0FBQyxHQUFHLHFCQUFVLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFBO0lBRXRDLCtDQUErQztJQUMvQyxJQUFNLENBQUMsR0FBRyxxQkFBVSxDQUFDLGFBQWEsQ0FBQyxNQUFNLENBQUMsZUFBZSxDQUFDLENBQUE7SUFDMUQsSUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7SUFFbEQsT0FBTztRQUNOLE1BQU0sRUFBRSxDQUFDLENBQUMsS0FBSyxFQUFFO1FBQ2pCLE1BQU0sRUFBRSxDQUFDLENBQUMsS0FBSyxFQUFFO0tBQ2pCLENBQUE7QUFDRixDQUFDLENBQUE7QUFqQlksUUFBQSxpQkFBaUIscUJBaUI3QjtBQUVNLElBQU0sYUFBYSxHQUFHLFVBQzVCLHFCQUE2QixFQUM3QixxQkFBNkIsRUFDN0IsSUFBWSxFQUNaLFFBQWdCLEVBQ2hCLFFBQWdCLEVBQ2hCLGtCQUEwQjtJQUUxQix1REFBdUQ7SUFDdkQsNEJBQTRCO0lBQzVCLDRFQUE0RTtJQUM1RSw2QkFBNkI7SUFDckIsSUFBQSxDQUFDLEdB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