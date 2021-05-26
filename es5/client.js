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
exports.verifySession = exports.deriveSession = exports.generateEphemeral = exports.deriveVerifier = exports.derivePrivateKey = exports.generateSalt = void 0;
var params = __importStar(require("./params"));
var srp_integer_1 = __importDefault(require("./srp-integer"));
var generateSalt = function () {
    // s    User's salt
    var s = srp_integer_1.default.randomInteger(params.hashOutputBytes);
    return s.toHex();
};
exports.generateSalt = generateSalt;
var derivePrivateKey = function (salt, username, password) {
    // H()  One-way hash function
    var H = params.H;
    // s    User's salt
    // I    Username
    // p    Cleartext Password
    var s = srp_integer_1.default.fromHex(salt);
    var I = String(username);
    var p = String(password);
    // x = H(s, H(I | p))  (s is chosen randomly)
    /** Editor's note
     * Error happening here on SRPInteger.fromHex: 'Expected string to be an even number of characters' when calling hexToArrayBuffer
     */
    var x = H(s, H(srp_integer_1.default.fromHex(I + ":" + p)));
    return x.toHex();
};
exports.derivePrivateKey = derivePrivateKey;
var deriveVerifier = function (privateKey) {
    // N    A large safe prime (N = 2q+1, where q is prime)
    // g    A generator modulo N
    var N = params.N, g = params.g;
    // x    Private key (derived from p and s)
    var x = srp_integer_1.default.fromHex(privateKey);
    // v = g^x                   (computes password verifier)
    var v = g.modPow(x, N);
    return v.toHex();
};
exports.deriveVerifier = deriveVerifier;
var generateEphemeral = function () {
    // N    A large safe prime (N = 2q+1, where q is prime)
    // g    A generator modulo N
    var N = params.N, g = params.g;
    // A = g^a                  (a = random number)
    var a = srp_integer_1.default.randomInteger(params.hashOutputBytes);
    var A = g.modPow(a, N);
    return {
        secret: a.toHex(),
        public: A.toHex(),
    };
};
exports.generateEphemeral = generateEphemeral;
var deriveSession = function (clientSecretEphemeral, serverPublicEphemeral, salt, username, privateKey) {
    // N    A large safe prime (N = 2q+1, where q is prime)
    // g    A generator modulo N
    // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
    // H()  One-way hash function
    var N = params.N, g = params.g, k = params.k, H = params.H;
    // a    Secret ephemeral values
    // B    Public ephemeral values
    // s    User's salt
    // I    Username
    // x    Private key (derived from p and s)
    var a = srp_integer_1.default.fromHex(clientSecretEphemeral);
    var B = srp_integer_1.default.fromHex(serverPublicEphemeral);
    var s = srp_integer_1.default.fromHex(salt);
    var I = String(username);
    var x = srp_integer_1.default.fromHex(privateKey);
    // A = g^a                  (a = random number)
    var A = g.modPow(a, N);
    // B % N > 0
    if (B.mod(N).equals(srp_integer_1.default.ZERO)) {
        // fixme: .code, .statusCode, etc.
        throw new Error('The server sent an invalid public ephemeral');
    }
    // u = H(A, B)
    var u = H(A, B);
    // S = (B - kg^x) ^ (a + ux)
    var S = B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N);
    // K = H(S)
    var K = H(S);
    // M = H(H(N) xor H(g), H(I), s, A, B, K)
    var M = H(H(N).xor(H(g)), H(srp_integer_1.default.fromHex(I)), s, A, B, K);
    return {
        key: K.toHex(),
        proof: M.toHex(),
    };
};
exports.deriveSession = deriveSession;
var verifySession = function (clientPublicEphemeral, clientSession, serverSessionProof) {
    // H()  One-way hash function
    var H = params.H;
    // A    Public ephemeral values
    // M    Proof of K
    // K    Shared, strong session key
    var A = srp_integer_1.default.fromHex(clientPublicEphemeral);
    var M = srp_integer_1.default.fromHex(clientSession.proof);
    var K = srp_integer_1.default.fromHex(clientSession.key);
    // H(A, M, K)
    var expected = H(A, M, K);
    var actual = srp_integer_1.default.fromHex(serverSessionProof);
    if (!actual.equals(expected)) {
        // fixme: .code, .statusCode, etc.
        throw new Error('Server provided session proof is invalid');
    }
};
exports.verifySession = verifySession;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xpZW50LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2NsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQ0EsK0NBQWtDO0FBQ2xDLDhEQUFzQztBQUUvQixJQUFNLFlBQVksR0FBRztJQUMzQixtQkFBbUI7SUFDbkIsSUFBTSxDQUFDLEdBQUcscUJBQVUsQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUFDLGVBQWUsQ0FBQyxDQUFBO0lBRTFELE9BQU8sQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO0FBQ2pCLENBQUMsQ0FBQTtBQUxZLFFBQUEsWUFBWSxnQkFLeEI7QUFFTSxJQUFNLGdCQUFnQixHQUFHLFVBQy9CLElBQVksRUFDWixRQUFnQixFQUNoQixRQUFnQjtJQUVoQiw2QkFBNkI7SUFDckIsSUFBQSxDQUFDLEdBQUssTUFBTSxFQUFYLENBQVc7SUFFcEIsbUJBQW1CO0lBQ25CLGdCQUFnQjtJQUNoQiwwQkFBMEI7SUFDMUIsSUFBTSxDQUFDLEdBQUcscUJBQVUsQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUE7SUFDbEMsSUFBTSxDQUFDLEdBQUcsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFBO0lBQzFCLElBQU0sQ0FBQyxHQUFHLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQTtJQUUxQiw2Q0FBNkM7SUFDN0M7O09BRUc7SUFDSCxJQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxxQkFBVSxDQUFDLE9BQU8sQ0FBSSxDQUFDLFNBQUksQ0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFBO0lBRWxELE9BQU8sQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO0FBQ2pCLENBQUMsQ0FBQTtBQXRCWSxRQUFBLGdCQUFnQixvQkFzQjVCO0FBRU0sSUFBTSxjQUFjLEdBQUcsVUFBQyxVQUFrQjtJQUNoRCx1REFBdUQ7SUFDdkQsNEJBQTRCO0lBQ3BCLElBQUEsQ0FB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