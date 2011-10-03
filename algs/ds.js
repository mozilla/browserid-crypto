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

var HASH_ALGS = {
  "sha1": null,
  "sha256": function(message) {return libs.sjcl.codec.hex.fromBits(libs.sjcl.hash.sha256.hash(message));}
};

function doHash(hashAlg, message, modulus) {
  // FIXME: conversion of hash needs review from FIPS186-3, appendix c.2
  // NO REALLY FIXME - I'm quite sure the modulus part is not cool 
  return new libs.BigInteger(HASH_ALGS[hashAlg](message), "16").mod(modulus);
}

// supported keysizes
// the Diffie-Hellman group is specified for each keysize
// this means we don't need to specify a parameter generation step.
var KEYSIZES = {
  // for testing only
  64: {
    p: "00f408ae0bcaf454a0c6a74517af870f496a13dd57eb84924da688be3d9d075130faf02f3871c1952f6c37acd7e306f5dc3d9b4c84936e0542b5ce559d06c84bf93420022e56591521a2a98d1f73f89a1a18d91d3c2bf149863616af1dd210a3a3676ce16ac0b37ba0b412cf2a2f9ccf0ffde5d6f45fd3a4f534cf9473cac00613",
    q: "00998798e396fb4e368b72b4cf4c610baa00fc8341",
    g: "7eed437fd5087b8c993f8f8c6ad72248737a5cfe3fce06626c4eb316b7d25e4747d49fd652772b726a667ea3ee45b05af8147271838e2fdac039276955af9adb0cb7a227d339dcf9d48cd2da17881dda47d30d5d9b2ca26e75bc0279c794bab94688381bc762de5e33cce504e428cb543662cda93ac740663310ac9b63b0e102",
    hashAlg: "sha256"
  },
  128: {
    p: "00f408ae0bcaf454a0c6a74517af870f496a13dd57eb84924da688be3d9d075130faf02f3871c1952f6c37acd7e306f5dc3d9b4c84936e0542b5ce559d06c84bf93420022e56591521a2a98d1f73f89a1a18d91d3c2bf149863616af1dd210a3a3676ce16ac0b37ba0b412cf2a2f9ccf0ffde5d6f45fd3a4f534cf9473cac00613",
    q: "00998798e396fb4e368b72b4cf4c610baa00fc8341",
    g: "7eed437fd5087b8c993f8f8c6ad72248737a5cfe3fce06626c4eb316b7d25e4747d49fd652772b726a667ea3ee45b05af8147271838e2fdac039276955af9adb0cb7a227d339dcf9d48cd2da17881dda47d30d5d9b2ca26e75bc0279c794bab94688381bc762de5e33cce504e428cb543662cda93ac740663310ac9b63b0e102",
    hashAlg: "sha256"
  },
  256: {
    p: "815901aa6d3ced6a0bd488c617351e322c8aef8f9f90adf331a2583d8082ac46f74345a1e1cf561facbdf3239bc3f0ee71618b5d016266caafd48439b034a38f6560cd6b671e3a80248b46809ad8de7a4cc7250469611d59dae8d8af5c6d0f9f3665f9857e04e1134dc94b270e93341449ea503617447ecb83b2c01602878c070d080da464c974d9951c35c1a553407345ee31ebc4a29a3488d5a54702a971ee0a1ea4da93fcf64105040893ff4bec23ca11e8cffa279e899a46891137c28e85f5a2fc9c637af6d26f6b5deba3d60580df41c334ea123331f8b0adeb43ea64a037e0c5ac168c47ce421bc9718ba8357099a0221f778599acd917607f3e3024d7",
    q: "87974deb793421ce3891540d906ac0806b85a2b95adc211a82ef8b659f8d9d25",
    g: "75ee80f0a161dd0c025ac818db8d52d193a46655fe0ebd3c289a949f42185f58f2f88f825dcdb3e3e98c0598af87599728f4f0719a8f68b133e82eb1bc4e3b6b8a377a5c6b812d656efcde578fdf515ac6ef628f1564ac907745d53bc6213b74f0cc303bbe68f3ab2220dcacd0ceece7aac3a675aaa0604885a1fb1374e6c08f2dcf503e58ac6487be73b8ab2a10fa62a79522cbc777b6321fd346e0d36ee5a7291955117d8bb4284901eb26804bd2286a14af52f5301c489c80dfeafb7ce496af58479a4c6f57f29ec8c9e4f6b88deb06f5d120859d2d4de06e57b0476f8263f7a4a35f67ed21a4a927109fa89a6b7f4976e98e3ddb3cd232c516b1da5cc555",
    hashAlg: "sha256"
  }
};

// turn the keysize params to bigints
for (keysize in KEYSIZES) {
  var the_params = KEYSIZES[keysize];
  the_params.p = new BigInteger(the_params.p, "16");
  the_params.q = new BigInteger(the_params.q, "16");
  the_params.g = new BigInteger(the_params.g, "16");
}


function _getKeySizeFromYBitlength(size) {
  for (keysize in KEYSIZES) {
    var keysize_nbits = KEYSIZES[keysize].p.bitLength();
    var diff = keysize_nbits - size;

    // extremely unlikely to be more than 30 bits smaller than p
    // 2^-30. FIXME: should we be more tolerant here.
    if (diff >= 0 && diff < 30) {
      return keysize;
    }
  }

  return null;
}

function randomNumberMod(q, rng) {
  // do a few more bits than q so we can wrap around with not too much bias
  // FIXME: is this a secure enough to get a reasonable distribution on x?
  return new libs.BigInteger(q.bitLength() + 5, rng).mod(q);
}

var KeyPair = function() {
  this.algorithm = "DS";
};

KeyPair.prototype = new jwk.KeyPair();

KeyPair.prototype.generate = function(keysize, progressCB, doneCB) {
  var params = KEYSIZES[keysize];
  if (!params)
    throw new exceptions.KeySizeNotSupportedException(keysize.toString());
  
  this.keysize= keysize;

  // FIXME: should we have a more global rng?
  var rng = new libs.SecureRandom();
  
  // DSA key gen: random x modulo q
  var x = randomNumberMod(params.q, rng);

  // the secret key will compute y
  this.secretKey = new SecretKey(x, this.keysize);
  this.publicKey = new PublicKey(this.secretKey.y, this.keysize);
  
  this.publicKey.algorithm = this.secretKey.algorithm = this.algorithm;

  if (!progressCB)
    return this;
  else
    doneCB(this);
};

var PublicKey = function(y, keysize) {
  this.y = y;
  this.keysize = keysize;
};

PublicKey.prototype = new jwk.PublicKey();

PublicKey.prototype.verify = function(message, signature) {
  var params = KEYSIZES[this.keysize];

  // extract r and s
  var split_sig = signature.split("|");
  var r = new BigInteger(split_sig[0], 16),
      s = new BigInteger(split_sig[1], 16);

  // check rangeconstraints
  if ((r.compareTo(libs.BigInteger.ZERO) < 0) || (r.compareTo(params.q) > 0)) {
    console.log("problem with r");
    return false;
  }
  if ((s.compareTo(libs.BigInteger.ZERO) < 0) || (s.compareTo(params.q) > 0)) {
    console.log("problem with s");
    return false;
  }

  var w = s.modInverse(params.q);
  var u1 = doHash(params.hashAlg, message, params.q).multiply(w).mod(params.q);
  var u2 = r.multiply(w).mod(params.q);
  var v = params.g
    .modPow(u1,params.p)
    .multiply(this.y.modPow(u2,params.p)).mod(params.p)
    .mod(params.q);

  return v.equals(r);
};

PublicKey.prototype.serializeToObject = function(obj) {
  obj.y = this.y.toString(16);
};

PublicKey.prototype.equals = function(other) {
  if (other == null)
    return false;
  
  return ((this.keysize == other.keysize) && (this.y.equals(other.y)));
};

PublicKey.prototype.deserializeFromObject = function(obj) {
  this.y = new libs.BigInteger(obj.y, 16);

  this.keysize = _getKeySizeFromYBitlength(this.y.bitLength());
  return this;
};

function SecretKey(x, keysize, y) {
  this.x = x;

  var params = KEYSIZES[keysize];

  // compute y if need be
  if (!y && params)
    y = params.g.modPow(this.x, params.p);
  this.y = y;
  
  this.keysize = keysize;
};

SecretKey.prototype = new jwk.SecretKey();

SecretKey.prototype.sign = function(message, progressCB, doneCB) {
  var params = KEYSIZES[this.keysize];

  // see https://secure.wikimedia.org/wikipedia/en/wiki/Digital_Signature_Algorithm

  // only using single-letter vars here because that's how this is defined in the algorithm
  var rng = new libs.SecureRandom();  
  var k, r, s;

  // do this until r != 0 (very unlikely, but hey)
  while(true) {
    k = randomNumberMod(params.q, rng);
    r = params.g.modPow(k, params.p).mod(params.q);
    
    if (r.equals(libs.BigInteger.ZERO))
      continue;

    // the hash
    var bigint_hash = doHash(params.hashAlg, message, params.q);
    
    // compute H(m) + (x*r)
    var message_dep = bigint_hash.add(this.x.multiply(r).mod(params.q)).mod(params.q);
    
    // compute s
    s = k.modInverse(params.q).multiply(message_dep).mod(params.q);

    if (s.equals(libs.BigInteger.ZERO))
      continue;

    // r and s are non-zero, we can continue
    break;
  }

  // format the signature, it's r and s
  var signature = r.toString(16) + "|" + s.toString(16);
  
  if (!progressCB)
    return signature;
  else
    doneCB(signature);
};

SecretKey.prototype.serializeToObject = function(obj) {
  obj.x = this.x.toString(16);
  obj.keysize = this.keysize;
};

SecretKey.prototype.deserializeFromObject = function(obj) {
  this.x = new BigInteger(obj.x, 16);
  this.keysize = obj.keysize;

  var params = KEYSIZES[keysize];
  
  // repetition, bad - FIXME
  this.y = params.g.modPow(this.x, params.p);

  return this;
};

// register this stuff 
jwk.KeyPair._register("DS", {
  KeyPair: KeyPair,
  PublicKey: PublicKey,
  SecretKey: SecretKey});

