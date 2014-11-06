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

exports.verify = function(signedObject, publicKey, now, cb) {
  jwcrypto.verify(signedObject, publicKey, function(err, payload) {
    if (err) return cb(err);

    var assertionParams = extractAssertionParamsFrom(payload);

    // check iat
    if (assertionParams.issuedAt) {
      if (assertionParams.issuedAt.valueOf() > now.valueOf())
        return cb(new VerificationError("issued later than verification date"));
    }

    // check exp expiration
    if (assertionParams.expiresAt) {
      if (assertionParams.expiresAt.valueOf() < now.valueOf()) {
        return cb(new VerificationError("expired"));
      }
    }

    cb(null, payload, assertionParams);
  });
};
