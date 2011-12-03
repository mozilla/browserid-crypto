/* A small and focused API that exposes our implementation of
 * JSON Web Signatures */

/** JWS constructor  */
exports.JWS = function(jwsEncoded) {
  throw "not implemented"; 
};

/** create a new JSON Web Signature instance.
 *    payload - a JSON object containing payload fields to sign
 *              (will be augmented with 'iat', 'exp')
 *    privKey - a JSON object containing the private key to use
 *              to sign the JWS.
 *    cb - A callback that will recieve two parameters,
 *         an error (null on success), and the created jws instance.
 */
exports.JWS.create = function(payload, privKey, cb) {
  setTimeout(function() { cb('not implemented'); }, 0);
};

/** decode an encoded jws string into a JWS instance */
exports.JWS.decode = function(jwsEncoded) {
  return new JWS(jwsEncoded);
} 

/** jws.verify() - instance method to verify the signature on a JSON Web
 *                 signature
 */
exports.JWS.prototype.verify = function(pubKey, cb) {
  setTimeout(function() { cb('not implemented'); }, 0);
};

/** jws.encode() - encode the token as a base64 encoded string */
exports.JWS.prototype.encode = function() {
  throw "not implemented";
  return undefined;
};

exports.JWS.prototype.sign = function(privKey, cb) {
  setTimeout(function() { cb('not implemented'); }, 0);
};

exports.generateKeypair = function(options, cb) {
  setTimeout(function() { cb('not implemented'); }, 0);
};
