/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var jwcrypto = require("./jwcrypto");
var assertion = require("./assertion");
var error = require("./error");
var utils = require("./utils");
var delay = utils.delay;
var MalformedError = error.MalformedError;
var VerificationError = error.VerificationError;

var serializeCertParamsInto = function(certParams, params) {
  params['public-key'] = certParams.publicKey.toSimpleObject();
  // now let's serialize all the client provided parameters into
  // the certificate.  If there is a duplicate parameter,
  // we'll throw an exception
  Object.keys(certParams).forEach(function(key) {
    if (params[key]) {
      throw new MalformedError("certificate param '" + key + "' defined multiple times");
    }
    if (key !== 'publicKey') {
      params[key] = certParams[key];
    }
  });
};

function extractCertParamsFrom(params) {
  var certParams = {};

  certParams.publicKey = jwcrypto.loadPublicKey(JSON.stringify(params['public-key']));
  delete params['public-key'];

  if (params.principal) {
    certParams.principal = params.principal;
    delete params.principal;
  }

  return certParams;
}

exports.sign = function(certParams, assertionParams, additionalPayload,
                        secretKey, cb) {
  var payload = {};
  utils.copyInto(additionalPayload || {}, payload);

  serializeCertParamsInto(certParams, payload);

  assertion.sign(payload, assertionParams, secretKey, cb);
};

var verify = function(signedObject, publicKey, now, cb) {
  assertion.verify(signedObject, publicKey, now, function(err, payload, assertionParams) {
    if (err)
      return cb(err);

    var originalComponents = jwcrypto.extractComponents(signedObject);
    var certParams = extractCertParamsFrom(payload, originalComponents);

    cb(err, payload, assertionParams, certParams);
  });
};

exports.verify = verify;

exports.bundle = function(certs, signedAssertion) {
  if (!certs || certs.length === 0) {
    throw new MalformedError("certificates must be a non-empty array");
  }
  return [].concat(certs, signedAssertion).join('~');
};

exports.unbundle = function(b) {
  var arr = b.split('~');
  var obj = {};
  obj.signedAssertion = arr.pop();
  obj.certs = arr;
  return obj;
};

// verify just a chain of certs
var verifyChain = function(certs, now, getRoot, cb) {
  if (!certs.length)
    return delay(cb)(new MalformedError("certs must be an array of at least one cert"));

  var rootIssuer;
  try {
    // the root
    rootIssuer = jwcrypto.extractComponents(certs[0]).payload.iss;
  } catch (ex) {
    // can't extract components
    return delay(cb)(ex);
  }

  // iterate through the certs
  function verifyCert(i, pk, certParamsArray, cb) {
    // do a normal verify on that cert
    verify(certs[i], pk, now, function(err, payload, assertionParams, certParams) {
      if (err) return cb(err);

      i += 1;
      certParamsArray.push({payload: payload,
                            assertionParams: assertionParams,
                            certParams: certParams});

      if (i >= certs.length)
        cb(null, certParamsArray, certParams.publicKey);
      else
        delay(verifyCert)(i, certParams.publicKey, certParamsArray, cb);
    });
  }

  // Get the root public key to start the chain.
  // There may be several candidate keys, in which case
  // we try each until we find one that works.
  getRoot(rootIssuer, function(err, rootPKs) {
    if (err) return delay(cb)(err);

    if (!Array.isArray(rootPKs)) {
      rootPKs = [rootPKs];
    } else if (rootPKs.length === 0) {
      return delay(cb)(new VerificationError('no public keys found for root issuer'));
    }

    function tryRootPK(kIdx) {
      verifyCert(0, rootPKs[kIdx], [], function(err, certParamsArray /* , lastPK */) {
        if (err) {
          // try the next key, or error out if we've tried them all
          kIdx++;
          if (kIdx >= rootPKs.length) {
            return cb(err);
          }
          return tryRootPK(kIdx);
        } else {
          // we're done
          cb(null, certParamsArray);
        }
      });
    }
    tryRootPK(0);
  });
};

exports.verifyChain = verifyChain;

exports.verifyBundle = function(bundle, now, getRoot, cb) {
  // unbundle
  if (typeof(bundle) !== 'string' && !(bundle instanceof String)) {
    return delay(cb)(new MalformedError("malformed backed assertion"));
  }

  var parsedBundle = exports.unbundle(bundle);
  var signedAssertion = parsedBundle.signedAssertion;
  var certs = parsedBundle.certs;

  // no certs? not okay
  if (certs.length === 0) {
    return delay(cb)(new MalformedError("no certificates provided"));
  }

  // verify the chain
  verifyChain(certs, now, getRoot, function(err, certParamsArray) {
    // ergonomic error messages
    if (err) return cb(err);

    // what was the last PK in the successful chain?
    var lastPK = certParamsArray[certParamsArray.length - 1].certParams.publicKey;

    // now verify the assertion
    assertion.verify(signedAssertion, lastPK, now, function(err, payload, assertionParams) {
      // ergonomic error messages
      if (err) return cb(err);

      // we're good!
      cb(null, certParamsArray, payload, assertionParams);
    });
  });
};
