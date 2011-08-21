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
    exceptions = require("./exceptions");

// supported keysizes
var KEYSIZES = {
  // for testing only
  64: {
    rsaKeySize: 512,
    hashAlg: "sha256"
  },
  256: {
    rsaKeySize: 2048,
    hashAlg: "sha256"
  }
};

var KeyPair = function() {
  this.algorithm = "RS";  
  this.keysize = null;
  this.publicKey = null;
  this.secretKey = null;
};

KeyPair.prototype = {
  getJWTAlgorithm: function() {
    return this.algorithm + this.keysize.toString();
  }
};

// FIXME: keysize should be the keysize that determines the
// whole JWT setup, e.g. 256 means RSA2048 with SHA256.
KeyPair.generate = function(keysize) {
  var k = new KeyPair();

  if (!(keysize in KEYSIZES))
    throw new exceptions.KeySizeNotSupportedException(keysize.toString());
  
  k.keysize= keysize;

  // generate RSA keypair
  var rsa = new libs.RSAKey();
  rsa.generate(KEYSIZES[keysize].rsaKeySize, "10001");

  // FIXME: should extract only public info for the public key
  k.publicKey = new PublicKey(rsa, keysize);
  k.secretKey = new SecretKey(rsa, keysize);

  return k;
};

var PublicKey = function(rsa, keysize) {
  this.rsa = rsa;
  this.keysize = keysize;
};

PublicKey.prototype = {
  verify: function(message, signature) {
    return this.rsa.verifyString(message, signature);
  }
};

var SecretKey = function(rsa, keysize) {
  this.rsa = rsa;
  this.keysize = keysize;
};

SecretKey.prototype = {
  sign: function(message) {
    return this.rsa.signString(message, KEYSIZES[this.keysize].hashAlg);
  }
};

exports.KeyPair = KeyPair;
