/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var   libs = require("../../libs/all"),
      algs = require("./index"),
BigInteger = libs.BigInteger;

// supported keysizes
var KEYSIZES = {
  // for testing only
  64: {
    rsaKeySize: 512,
    hashAlg: "sha256"
  },
  128: {
    rsaKeySize: 1024,
    hashAlg: "sha256"
  },
  256: {
    rsaKeySize: 2048,
    hashAlg: "sha256"
  }
};

function _getKeySizeFromRSAKeySize(bits) {
  for (var keysize in KEYSIZES) {
    // we tolerate one bit off from the keysize
    if (Math.abs(KEYSIZES[keysize].rsaKeySize-bits) <= 1)
      return keysize;
  }

  throw new algs.KeySizeNotSupportedError("bad key size: " + bits);
}

function generate(keysize, rng, cb) {
  if (!(keysize in KEYSIZES))
    throw new algs.KeySizeNotSupportedError(keysize.toString());

  var keypair = new algs.KeyPair();
  keypair.keysize= keysize;

  // generate RSA keypair
  keypair.rsa = new libs.RSAKey();
  keypair.rsa.generate(KEYSIZES[keysize].rsaKeySize, "10001");

  // FIXME: should extract only public info for the public key
  keypair.publicKey = new PublicKey(keypair.rsa, keysize);
  keypair.secretKey = new SecretKey(keypair.rsa, keysize);

  keypair.publicKey.algorithm = keypair.secretKey.algorithm = keypair.algorithm = 'RS';

  // XXX - timeout or nexttick?
  cb(null, keypair);
}

var PublicKey = function(rsa, keysize) {
  this.rsa = rsa;
  this.keysize = keysize;
};

PublicKey.prototype = new algs.PublicKey();

PublicKey.prototype.verify = function(message, signature, cb) {
  cb(null, this.rsa.verifyString(message, signature));
};

PublicKey.prototype.serializeToObject = function (obj) {
  obj.n = this.rsa.n.toString(10);
  obj.e = this.rsa.e.toString(10);
};

PublicKey.prototype.equals = function(other) {
  if (other == null)
    return false;

  // FIXME: this is loser-ville if e is not an integer
  return ((this.rsa.n.equals(other.rsa.n)) && (this.rsa.e === other.rsa.e || this.rsa.e.equals(other.rsa.e)) && (this.algorithm === other.algorithm));
};

PublicKey.prototype.deserializeFromObject = function(obj) {
  // Allow import from newer-style JWK-compatible keys
  // as well as older-style BrowserID-format keys.
  this.rsa = new libs.RSAKey();
  if (obj.kty) {
    this.rsa.n = libs.BigInteger.fromBase64(obj.n);
    this.rsa.e = libs.BigInteger.fromBase64(obj.e);
  } else {
    this.rsa.n = new libs.BigInteger(obj.n, 10);
    this.rsa.e = new libs.BigInteger(obj.e, 10);
  }
  this.keysize = _getKeySizeFromRSAKeySize(this.rsa.n.bitLength());
  return this;
};

function SecretKey(rsa, keysize) {
  this.rsa = rsa;
  this.keysize = keysize;
}

SecretKey.prototype = new algs.SecretKey();

SecretKey.prototype.sign = function(message, rng, progressCB, doneCB) {
  var signature = this.rsa.signString(message, KEYSIZES[this.keysize].hashAlg);
  if (!progressCB)
    return signature;
  else
    doneCB(signature);
};

SecretKey.prototype.serializeToObject = function(obj) {
  obj.n = this.rsa.n.toString(10);
  obj.e = this.rsa.e.toString(10);
  obj.d = this.rsa.d.toString(10);
};

SecretKey.prototype.deserializeFromObject = function(obj) {
  // Allow import from newer-style JWK-compatible keys
  // as well as older-style BrowserID-format keys.
  this.rsa = new libs.RSAKey();
  if (obj.kty) {
    this.rsa.n = BigInteger.fromBase64(obj.n);
    this.rsa.e = BigInteger.fromBase64(obj.e);
    this.rsa.d = BigInteger.fromBase64(obj.d);
  } else {
    this.rsa.n = new BigInteger(obj.n, 10);
    this.rsa.e = new BigInteger(obj.e, 10);
    this.rsa.d = new BigInteger(obj.d, 10);
  }
  this.keysize = _getKeySizeFromRSAKeySize(this.rsa.n.bitLength());
  return this;
};

// register this stuff
algs.register("RS", {
  generate: generate,
  PublicKey: PublicKey,
  SecretKey: SecretKey
});
// For compatiblity with JWK 'kty' param values.
algs.register("RSA", {
  generate: generate,
  PublicKey: PublicKey,
  SecretKey: SecretKey
});
