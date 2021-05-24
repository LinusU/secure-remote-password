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
    // x = H(s, H(I | ':' | p))  (s is chosen randomly)
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xpZW50LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vc3JjL2NsaWVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQ0EsK0NBQWtDO0FBQ2xDLDhEQUFzQztBQUUvQixJQUFNLFlBQVksR0FBRztJQUMzQixtQkFBbUI7SUFDbkIsSUFBTSxDQUFDLEdBQUcscUJBQVUsQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUFDLGVBQWUsQ0FBQyxDQUFBO0lBRTFELE9BQU8sQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO0FBQ2pCLENBQUMsQ0FBQTtBQUxZLFFBQUEsWUFBWSxnQkFLeEI7QUFFTSxJQUFNLGdCQUFnQixHQUFHLFVBQy9CLElBQVksRUFDWixRQUFnQixFQUNoQixRQUFnQjtJQUVoQiw2QkFBNkI7SUFDckIsSUFBQSxDQUFDLEdBQUssTUFBTSxFQUFYLENBQVc7SUFFcEIsbUJBQW1CO0lBQ25CLGdCQUFnQjtJQUNoQiwwQkFBMEI7SUFDMUIsSUFBTSxDQUFDLEdBQUcscUJBQVUsQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUE7SUFDbEMsSUFBTSxDQUFDLEdBQUcsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFBO0lBQzFCLElBQU0sQ0FBQyxHQUFHLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQTtJQUUxQixtREFBbUQ7SUFDbkQsSUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMscUJBQVUsQ0FBQyxPQUFPLENBQUksQ0FBQyxTQUFJLENBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQTtJQUVsRCxPQUFPLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtBQUNqQixDQUFDLENBQUE7QUFuQlksUUFBQSxnQkFBZ0Isb0JBbUI1QjtBQUVNLElBQU0sY0FBYyxHQUFHLFVBQUMsVUFBa0I7SUFDaEQsdURBQXVEO0lBQ3ZELDRCQUE0QjtJQUNwQixJQUFBLENBQUMsR0FBUSxNQUFN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