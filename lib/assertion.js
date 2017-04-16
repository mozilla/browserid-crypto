/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var jwcrypto = require("./jwcrypto");
var utils = require("./utils");
var VerificationError = require("./error").VerificationError;

var serializeAssertionParamsInto = function(assertionParams, params) {
  // copy over only the parameters we care about into params
  params.iat = assertionParams.issuedAt ? assertionParams.issuedAt.valueOf() : undefined;
  params.exp = assertionParams.expiresAt ? assertionParams.expiresAt.valueOf() : undefined;
  params.iss = assertionParams.issuer;
  params.aud = assertionParams.audience;
};

function extractAssertionParamsFrom(params) {
  var assertionParams = {};
  assertionParams.issuedAt = utils.getDate(params.iat);
  assertionParams.expiresAt = utils.getDate(params.exp);
  assertionParams.issuer = params.iss;
  assertionParams.audience = params.aud;

  delete params.iat;
  delete params.exp;
  delete params.iss;
  delete params.aud;

  return assertionParams;
}

exports.sign = function(payload, assertionParams, secretKey, cb) {
  var allParams = {};
  utils.copyInto(payload, allParams);
  serializeAssertionParamsInto(assertionParams, allParams);

  jwcrypto.sign(allParams, secretKey, cb);
};

exports.verify = function(signedObject, publicKey, now, options, cb) {
  // by default, allow the issuer's clock to be up to 10 seconds ahead of
  // ours, or up to 120 seconds behind. Callers can control this by passing
  // in other values (in seconds).
  var tolerateOld = 120 * 1000;
  var tolerateNew = 10 * 1000;
  if (typeof options === 'function') {
    cb = options;
  } else {
    if (options && options.tolerateOld) {
      tolerateOld = options.tolerateOld * 1000;
    }
    if (options && options.tolerateNew) {
      tolerateNew = options.tolerateNew * 1000;
    }
  }

  jwcrypto.verify(signedObject, publicKey, function(err, payload) {
    if (err) return cb(err);

    var assertionParams = extractAssertionParamsFrom(payload);

    // check iat
    if (assertionParams.issuedAt) {
      if (assertionParams.issuedAt.valueOf() > now.valueOf() + tolerateNew) {
        return cb(new VerificationError("issued later than verification date"));
      }
    }

    // check exp expiration
    if (assertionParams.expiresAt) {
      if (assertionParams.expiresAt.valueOf() < now.valueOf() - tolerateOld) {
        return cb(new VerificationError("expired"));
      }
    }

    cb(null, payload, assertionParams);
  });
};
