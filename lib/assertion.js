/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var jwcrypto = require("./jwcrypto");
var utils = require("./utils");
var VerificationError = require("./error").VerificationError;

var serializeAssertionParamsInto = function(assertionParams, params) {
  // copy over only the parameters we care about into params
  params.iat = assertionParams.issuedAt ? Math.floor(assertionParams.issuedAt.valueOf() / 1000) : undefined;
  params.exp = assertionParams.expiresAt ? Math.floor(assertionParams.expiresAt.valueOf() / 1000) : undefined;
  params.iss = assertionParams.issuer;
  params.aud = assertionParams.audience;
};

function extractAssertionParamsFrom(params, newFormat) {
  var assertionParams = {};
  if (newFormat) {
    assertionParams.issuedAt = utils.getDateFromSeconds(params.iat);
    assertionParams.expiresAt = utils.getDateFromSeconds(params.exp);
  } else {
    assertionParams.issuedAt = utils.getDate(params.iat);
    assertionParams.expiresAt = utils.getDate(params.exp);
  }
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

    // pass if the public key passed in is "newFormat", that means the assertion
    // is as well.  This means we should interpret some values differently (namely
    // times are in seconds).
    // This trick leverages the fact that consumers of jwcrypto never consider
    // "assertions" in isolation from the certificate that they are combined with.
    var assertionParams = extractAssertionParamsFrom(payload, publicKey.newFormat);

    // check iat
    if (assertionParams.issuedAt) {
      // Allow for 10 seconds of future clock skew
      var futureSkew = 10 * 1000;
      if (assertionParams.issuedAt.valueOf() > now.valueOf() + futureSkew)
        return cb(new VerificationError("issued later than verification date"));
    }

    // check exp expiration
    if (assertionParams.expiresAt) {
      var pastSkew = 120 * 1000;
      if (assertionParams.expiresAt.valueOf() < now.valueOf() - pastSkew) {
        return cb(new VerificationError("expired"));
      }
    }

    cb(null, payload, assertionParams);
  });
};
