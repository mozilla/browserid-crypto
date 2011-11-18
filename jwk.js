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
 *     Michael Hanson <mhanson@mozilla.com>
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

var libs = require("./libs/all"),
    utils = require("./utils");

function NoSuchAlgorithmException(message) {
  this.message = message;
  this.toString = function() { return "No such algorithm: "+this.message; };
}
function NotImplementedException(message) {
  this.message = message;
  this.toString = function() { return "Not implemented: "+this.message; };
}

//
// signature functionality, specific to JWS
//

var ALGS = {
};

function NotImplementedException(message) {
  this.message = message;
  this.toString = function() { return "Not implemented: "+this.message; };
}

function KeyPair() {
  this.publicKey = null;
  this.secretKey = null;
  this.algorithm = null;
  this.keysize = null;
};

var _getAlgorithm = function _getAlgorithm() {
  return this.algorithm + this.keysize.toString();  
};

KeyPair.prototype = {
  getAlgorithm: _getAlgorithm
};

/*
 * the progressCB is called every so often
 * the system will auto-yield to the UI thread right
 * after each progressCB
 *
 * progressCB may be called with an estimated fraction
 * of work done, or with nothing
 */
KeyPair.generate = function(alg, keysize, progressCB, doneCB) {
  if (progressCB && !doneCB)
    throw "need a done callback if progress callback is included";
  
  if (!ALGS[alg])
    throw new NotImplementedException("algorithm " + alg + " not implemented");

  var kp = new ALGS[alg].KeyPair();

  // pass the callbacks
  kp.generate(keysize, progressCB, doneCB);

  // don't return anything if it's asynchronous
  if (!progressCB)
    return kp;
};

KeyPair._register = function(alg, cls) {
  ALGS[alg] = cls;
};

function PublicKey() {
}

PublicKey.prototype = {
  // produce a ready-to-be-JSON'ed object
  toSimpleObject: function() {
    var obj = {algorithm: this.algorithm};
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
  if (!ALGS[obj.algorithm])
    throw new NotImplementedException("no such algorithm: " + obj.algorithm);

  var pk = new ALGS[obj.algorithm].PublicKey();
  pk.algorithm = obj.algorithm;
  pk.deserializeFromObject(obj);
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
    var obj = {algorithm: this.algorithm};
    this.serializeToObject(obj);
    return obj;
  },
  
  serialize: function() {
    return JSON.stringify(this.toSimpleObject());
  },

  getAlgorithm: _getAlgorithm

};

SecretKey.fromSimpleObject = function(obj) {
  if (!ALGS[obj.algorithm])
    throw new NotImplementedException("no such algorithm: " + obj.algorithm);

  var sk = new ALGS[obj.algorithm].SecretKey();
  sk.algorithm = obj.algorithm;
  sk.deserializeFromObject(obj);
  return sk;
};

SecretKey.deserialize = function(str) {
  var obj = JSON.parse(str);
  return SecretKey.fromSimpleObject(obj);
};


exports.KeyPair = KeyPair;
exports.PublicKey = PublicKey;
exports.SecretKey = SecretKey;

// algorithms
// FIXME: rs should self-register and should be added after this JWK definition
var rs = require("./algs/rs");
var ds = require("./algs/ds");

