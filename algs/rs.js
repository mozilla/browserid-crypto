/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is trusted.js; substantial portions derived
 * from XAuth code originally produced by Meebo, Inc., and provided
 * under the Apache License, Version 2.0; see http://github.com/xauth/xauth
 *
 * Contributor(s):
 *     Ben Adida <benadida@mozilla.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

var libs = require("../libs/all"),
    exceptions = require("./exceptions"),
    jwk = require("../jwk");

var BigInteger = libs.BigInteger;

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
  for (keysize in KEYSIZES) {
    // we tolerate one bit off from the keysize
    if (Math.abs(KEYSIZES[keysize].rsaKeySize-bits) <= 1)
      return keysize;
  }

  console.log("whoops keysize of " + bits);
  throw new exceptions.KeySizeNotSupportedException("bad key");
}

var KeyPair = function() {
  this.algorithm = "RS";
};

KeyPair.prototype = new jwk.KeyPair();

KeyPair.prototype.generate = function(keysize, progressCB, doneCB) {
  if (!(keysize in KEYSIZES))
    throw new exceptions.KeySizeNotSupportedException(keysize.toString());
  
  this.keysize= keysize;

  // generate RSA keypair
  this.rsa = new libs.RSAKey();
  this.rsa.generate(KEYSIZES[keysize].rsaKeySize, "10001");

  // FIXME: should extract only public info for the public key
  this.publicKey = new PublicKey(this.rsa, keysize);
  this.secretKey = new SecretKey(this.rsa, keysize);

  this.publicKey.algorithm = this.secretKey.algorithm = this.algorithm;

  if (!progressCB)
    return this;
  else
    doneCB(this);
};

var PublicKey = function(rsa, keysize) {
  this.rsa = rsa;
  this.keysize = keysize;
};

PublicKey.prototype = new jwk.PublicKey();

PublicKey.prototype.verify = function(message, signature) {
  return this.rsa.verifyString(message, signature);
};

PublicKey.prototype.serializeToObject = function(obj) {
  obj.n = this.rsa.n.toString();
  obj.e = this.rsa.e.toString();
  // obj.value = this.rsa.serializePublicASN1();
};

PublicKey.prototype.equals = function(other) {
  if (other == null)
    return false;
  
  // FIXME: this is loser-ville if e is not an integer
  return ((this.rsa.n.equals(other.rsa.n)) && (this.rsa.e == other.rsa.e || this.rsa.e.equals(other.rsa.e)) && (this.algorithm == other.algorithm));
};

PublicKey.prototype.deserializeFromObject = function(obj) {
  this.rsa = new libs.RSAKey();
  this.rsa.n = new libs.BigInteger(obj.n, 10);
  this.rsa.e = new libs.BigInteger(obj.e, 10);
  // this.rsa.readPublicKeyFromPEMString(obj.value);

  this.keysize = _getKeySizeFromRSAKeySize(this.rsa.n.bitLength());
  return this;
};

function SecretKey(rsa, keysize) {
  this.rsa = rsa;
  this.keysize = keysize;
};

SecretKey.prototype = new jwk.SecretKey();

SecretKey.prototype.sign = function(message) {
  return this.rsa.signString(message, KEYSIZES[this.keysize].hashAlg);
};

SecretKey.prototype.serializeToObject = function(obj) {
  // obj.value = this.rsa.serializePrivateASN1();
  obj.n = this.rsa.n.toString();
  obj.e = this.rsa.e.toString();
  obj.d = this.rsa.d.toString();
};

SecretKey.prototype.deserializeFromObject = function(obj) {
  this.rsa = new libs.RSAKey();
  // this.rsa.readPrivateKeyFromPEMString(obj.value);
  this.rsa.n = new BigInteger(obj.n, 10);
  this.rsa.e = new BigInteger(obj.e, 10);
  this.rsa.d = new BigInteger(obj.d, 10);

  this.keysize = _getKeySizeFromRSAKeySize(this.rsa.n.bitLength());
  return this;
};

// register this stuff 
jwk.KeyPair._register("RS", {
  KeyPair: KeyPair,
  PublicKey: PublicKey,
  SecretKey: SecretKey});

