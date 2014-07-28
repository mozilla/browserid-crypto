/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * the new jwcrypto API
 */

var algs = require("./algs/index"),
    error = require("./error"),
    utils = require("./utils"),
    delay = utils.delay,
    rng = require("./rng");

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
  for (var i = 0; i < POST_SEED_CALLBACKS.length; i++) {
    POST_SEED_CALLBACKS[i]();
  }

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

exports.generateKeypair = function(opts, cb) {
  cb = delay(cb);
  var algObject = algs.findAlgorithm(opts.algorithm);
  if (!algObject)
    throw new algs.NotImplementedError("algorithm " + opts.algorithm + " not implemented");

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
  if (typeof(signedObject) !== 'string') {
    throw new error.MalformedError("malformed signature");
  }

  var parts = signedObject.split(".");
  if (parts.length !== 3) {
    throw new error.MalformedError("signed object must have three parts, this one has " + parts.length);
  }

  function try_(name, fn) {
    try {
      return fn();
    } catch (ex) {
      if (ex instanceof error.JwcryptoError) {
        ex.message = name + ' segment: ' + ex.message;
        throw ex;
      } else if (ex instanceof SyntaxError) {
        throw new error.MalformedError(name + "segment: invalid json");
      } else {
        throw new error.MalformedError(name + "segment: malformed object");
      }
    }
  }

  var headerSegment = parts[0];
  var payloadSegment = parts[1];
  var cryptoSegment = parts[2];

  // we verify based on the actual string
  // FIXME: we should validate that the header contains only proper fields
  var header = try_('header', function() { return JSON.parse(utils.base64urldecode(headerSegment)); });
  var payload = try_('payload', function() { return JSON.parse(utils.base64urldecode(payloadSegment)); });
  var signature = try_('signature', function() { return utils.b64urltohex(cryptoSegment); });

  return {header: header,
          payload: payload,
          signature: signature,
          headerSegment: headerSegment,
          payloadSegment: payloadSegment,
          cryptoSegment: cryptoSegment};
};

exports.extractComponents = extractComponents;

exports.verify = function(signedObject, publicKey, cb) {
  var components;

  cb = delay(cb);
  try {
    components = extractComponents(signedObject);

    // check that algorithm matches
    if (publicKey.getAlgorithm() !== components.header.alg) {
      cb(new error.MalformedError("algorithms do not match"));
      return;
    }
  } catch (ex) {
    cb(ex);
    return;
  }

  // decode the signature, and verify it
  publicKey.verify(components.headerSegment + "." + components.payloadSegment, components.signature, function(err, result) {
    if (err)
      return cb(err);

    if (!result)
      return cb(new error.VerificationError("invalid signature"));

    return cb(null, components.payload);
  });
};

// entropy here is a string that is expected to be relatively high entropy
exports.addEntropy = function(entropy) {
  RNG.addEntropy(entropy);
};

exports.assertion = require("./assertion");
exports.cert = require("./cert");
exports.error = error;
