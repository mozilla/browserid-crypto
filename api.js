/* A small and focused API that exposes our implementation of
 * JSON Web Signatures */

const
jwk = require('./jwk'),
utils = require('./utils');

const 
DEFAULT_EXP_PERIOD_MS = (2 * 60 * 1000);

const internal_allocation = function() {};

/** JWS constructor  */
exports.JWS = function(jwsEncoded) {
  if (jwsEncoded === internal_allocation) return;
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
  if (typeof cb !== 'function') throw "missing required callback argument"; 

  setTimeout(function() {
    if (!payload) payload = {};
    // check 'iat' (time of issue of JWS)
    payload.iat = new Date().getTime();
    // check 'exp' (expiration date of JWS)
    if (!payload.exp) {
      payload.exp = new Date((new Date()).getTime() + DEFAULT_EXP_PERIOD_MS);
    }

    // NOTE: iss, aud, typ, nbf, or app specific keys *may* be provided by the 0
    var jws = new exports.JWS(internal_allocation);
    jws._payload = payload;
    jws._header = { alg: privKey.getAlgorithm() }; 
    jws._parts = [];
    jws._parts.push(utils.base64urlencode(JSON.stringify(jws._header)));
    jws._parts.push(utils.base64urlencode(JSON.stringify(jws._payload)));
    jws._parts.push(utils.hex2b64urlencode(privKey.sign(jws._parts.join('.'))));
    
    cb(null, jws);
  }, 0);
};

const dateFields = [ 'nbf', 'iat', 'exp' ];

function datesToSeconds(payload) {

}

function secondsToDates(payload) {
  
}


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

/** jws.payload() - get the JWS's JSON payload */
exports.JWS.prototype.payload = function() {
  var rv = JSON.parse(JSON.stringify(this._payload));
  // XXX: transform dates
  return rv;
};

exports.generateKeypair = function(options, cb) {
  if (typeof cb !== 'function') throw "missing required callback argument"; 

  setTimeout(function() {
    try {
      var bits = 256;
      if (typeof options.bits === 'string') bits = parseInt(options.bits, 10);
      else if (options.bits) bits = options.bits;

      if ([ 64, 128, 256 ].indexOf(bits) === -1) {
        throw "invalid key length (options.bits mis-set)"; 
      }

      var alg = 'DS';
      if (options.algorithm) alg = options.algorithm.substr(0,2).toUpperCase();
      
      if ([ 'DS', 'RS' ].indexOf(alg) === -1) {
        throw "invalid key length (options.bits mis-set)"; 
      }

      var keypair = jwk.KeyPair.generate(alg, bits);

      cb(null, keypair);
    } catch(e) {
      cb(e.toString());
    }
  }, 0);
};

createCert {

}

createAssertion {

}
