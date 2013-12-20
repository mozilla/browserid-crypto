/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * baseline objects for all algorithms
 */

var ALGS = { };
var ALIASES = { };

function KeySizeNotSupportedException(message) {
  this.message = message;
  this.toString = function() { return "Key size not supported: "+this.message; };
}

function NotImplementedException(message) {
  this.message = message;
  this.toString = function() { return "Not implemented: "+this.message; };
}

function KeyPair() {
  this.publicKey = null;
  this.secretKey = null;
  this.algorithm = null;
  this.keysize = null;
}

var _getAlgorithm = function _getAlgorithm() {
  return this.algorithm.substr(0,2) + this.keysize.toString();
};

KeyPair.prototype = {
  getAlgorithm: _getAlgorithm
};

exports.register = function(alg, cls) {
  ALGS[alg] = cls;
};

exports.registerAlias = function(alias, canonical) {
  ALIASES[alias] = canonical;
};

exports.findAlgorithm = function(objOrStr) {
  if (typeof objOrStr === 'string') {
    objOrStr = { kty: objOrStr };
  }
  objOrStr = extractAlg(objOrStr);

  return objOrStr ? ALGS[objOrStr] : undefined;
};

function extractAlg(obj) {
  var origAlg = obj.algorithm || obj.kty;
  var alg = ALIASES[origAlg] || origAlg;

  if (!ALGS[alg]) {
    throw new NotImplementedException("no such algorithm: " + origAlg);
  }
  return alg;
}

function PublicKey() {
}

PublicKey.prototype = {
  // produce a ready-to-be-JSON'ed object
  toSimpleObject: function() {
    var obj = {kty: this.algorithm};
    this.serializeToObject(obj);
    return obj;
  },

  // ok, JSON'ify it
  serialize: function() {
    return JSON.stringify(this.toSimpleObject());
  },

  getAlgorithm : _getAlgorithm
};

PublicKey.fromSimpleObject = function(obj) {
  var alg = extractAlg(obj);
  var pk = new ALGS[alg].PublicKey();
  pk.algorithm = alg;
  pk.deserializeFromObject(obj);
  // .kty implies that this key is "newFormat".  we can use this
  // knowledge in other places to handle both new and old data
  // formats.  we'll record it on the object.
  pk.newFormat = !!obj.kty;
  return pk;
};

PublicKey.deserialize = function(str) {
  var obj = JSON.parse(str);
  return PublicKey.fromSimpleObject(obj);
};


function SecretKey() {
}

SecretKey.prototype = {
  toSimpleObject: function() {
    var obj = {kty: this.algorithm};
    this.serializeToObject(obj);
    return obj;
  },

  serialize: function() {
    return JSON.stringify(this.toSimpleObject());
  },

  getAlgorithm: _getAlgorithm

};

SecretKey.fromSimpleObject = function(obj) {
  var alg = extractAlg(obj);
  var sk = new ALGS[alg].SecretKey();
  sk.algorithm = alg;
  sk.deserializeFromObject(obj);
  // .kty implies that this key is "newFormat".  we can use this
  // knowledge in other places to handle both new and old data
  // formats.  we'll record it on the object.
  sk.newFormat = !!obj.kty;
  return sk;
};

SecretKey.deserialize = function(str) {
  var obj = JSON.parse(str);
  return SecretKey.fromSimpleObject(obj);
};

exports.ALGS = ALGS;
exports.PublicKey = PublicKey;
exports.SecretKey = SecretKey;
exports.KeyPair = KeyPair;
exports.KeySizeNotSupportedException = KeySizeNotSupportedException;
exports.NotImplementedException = NotImplementedException;
