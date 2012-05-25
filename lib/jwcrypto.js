/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * the new jwcrypto API
 */

var algs = require("./algs/index"),
    utils = require("./utils"),
    delay = utils.delay,
    rng = require("./rng"),
    libs = require("../libs/minimal");

var RNG = new rng.RNG();

var IS_SEEDED = false;
var POST_SEED_CALLBACKS = [];

// start autoseeding
// queue up the things waiting for seeds
RNG.autoseed(function() {
  // mark this true so that, in case some of the callbacks in
  // POST_SEED_CALLBACKS do asynchronous things, the POST_SEED_CALLBACKS
  // array will no longer be modified.
  IS_SEEDED = true;

  // go through callbacks
  POST_SEED_CALLBACKS.forEach(function(one_cb) {
    one_cb();
  });

  // clean up as null so that weird egregious errors will
  // show up (e.g. double seeding.)
  POST_SEED_CALLBACKS = null;
});

function waitForSeed(doStuff) {
  if (IS_SEEDED) {
    return doStuff();
  } else {
    POST_SEED_CALLBACKS.push(doStuff);
  }
}

function NoSuchAlgorithmException(message) {
  this.message = message;
  this.toString = function() { return "No such algorithm: "+this.message; };
}

function MalformedException(message) {
  this.message = message;
  this.toString = function() { return "malformed input: "+this.message; };
}

exports.generateKeypair = function(opts, cb) {
  cb = delay(cb);
  var algObject = algs.ALGS[opts.algorithm];
  if (!algObject)
    throw new algs.NotImplementedException("algorithm " + opts.algorithm + " not implemented");
    
  waitForSeed(function() {
    // generate on the specific algorithm
    // no progress callback
    algObject.generate(opts.keysize, RNG, cb);
  });
};

exports.loadPublicKey = function(str) {
  return algs.PublicKey.deserialize(str);
};

exports.loadPublicKeyFromObject = function(obj) {
  return algs.PublicKey.fromSimpleObject(obj);
};

exports.loadSecretKey = function(str) {
  return algs.SecretKey.deserialize(str);  
};

exports.loadSecretKeyFromObject = function(obj) {
  return algs.SecretKey.fromSimpleObject(obj);
};


exports.sign = function(payload, secretKey, cb) {
  var header = {"alg": secretKey.getAlgorithm()};
  var algBytes = utils.base64urlencode(JSON.stringify(header));
  var jsonBytes = utils.base64urlencode(JSON.stringify(payload));

  waitForSeed(function() {
    secretKey.sign(algBytes + "." + jsonBytes, RNG, function() {}, function(rawSignature) {
      var signatureValue = utils.hex2b64urlencode(rawSignature);
      
      delay(cb)(null, algBytes + "." + jsonBytes + "." + signatureValue);
    });
  });
};

// extract components
var extractComponents = function(signedObject) {
  if (typeof(signedObject) != 'string')
    throw new MalformedException("malformed signature");
  
  var parts = signedObject.split(".");
  if (parts.length != 3) {
    throw new MalformedException("signed object must have three parts, this one has " + parts.length);
  }    
  
  var headerSegment = parts[0];
  var payloadSegment = parts[1];
  var cryptoSegment = parts[2];  

  // we verify based on the actual string
  // FIXME: we should validate that the header contains only proper fields
  var header = JSON.parse(utils.base64urldecode(headerSegment));
  var payload = JSON.parse(utils.base64urldecode(payloadSegment));
  var signature = utils.b64urltohex(cryptoSegment);

  return {header: header,
          payload: payload,
          signature: signature,
          headerSegment: headerSegment,
          payloadSegment: payloadSegment,
          cryptoSegment: cryptoSegment};
};

exports.extractComponents = extractComponents;

exports.verify = function(signedObject, publicKey, cb) {
  cb = delay(cb);
  try {
    var components = extractComponents(signedObject);
    
    // check that algorithm matches
    if (publicKey.getAlgorithm() != components.header.alg) {
      cb("invalid signature");
      return;
    }    
  } catch (x) {
    cb("malformed signature");
    return;
  }

  // decode the signature, and verify it
  publicKey.verify(components.headerSegment + "." + components.payloadSegment, components.signature, function(err, result) {
    if (err)
      return cb("malformed signature");
    
    if (!result)
      return cb("invalid signature");

    return cb(null, components.payload);
  });
};

//
// probably for future stuff
//

// for symmetric keys, it's plural because encryption and MACing.
exports.generateKeys = function(opts, cb) {
  
};


exports.encrypt = function(payload, key) {
  var rawKey = JSON.parse(key);
  var jsonBlob = libs.sjcl.json.encrypt(rawKey, payload, {ks: 128, ts: 64, cipher: 'aes', mode: 'ccm'});
  return utils.base64urlencode(jsonBlob);
};

exports.decrypt = function(encryptedPayload, key) {
  var jsonBlob = utils.base64urldecode(encryptedPayload);
  var rawKey = JSON.parse(key);
  return libs.sjcl.json.decrypt(rawKey, jsonBlob, {ks: 128, ts: 64, cipher: 'aes', mode: 'ccm'});
};

// entropy here is a string that is expected to be relatively high entropy
exports.addEntropy = function(entropy) {
  RNG.addEntropy(entropy);
};

exports.assertion = require("./assertion");
exports.cert = require("./cert");
