/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const jwcrypto = require("./jwcrypto"),
      utils = require("./utils");

function serializeAssertionParamsInto(assertionParams, params) {
  // copy over only the parameters we care about into params
  // XXX - fix weird params
  params.iat = assertionParams.iat ? assertionParams.iat.valueOf() : undefined;
  params.exp = assertionParams.exp ? assertionParams.exp.valueOf() : undefined;
  params.iss = assertionParams.iss;
}

function extractAssertionParamsFrom(params) {
  var assertionParams = {};
  assertionParams.iat = utils.getDate(params.iat);
  assertionParams.exp = utils.getDate(params.exp);
  assertionParams.iss = params.iss;

  delete params.iat;
  delete params.exp;
  delete params.iss;
  return assertionParams;
};

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
    if (assertionParams.iat) {
      if (assertionParams.iat.valueOf() > now.valueOf())
        return cb("assertion issued later than verification date");
    }

    // check exp expiration
    if (assertionParams.exp) {
      if (assertionParams.exp.valueOf() < now.valueOf())
        return cb("assertion has expired");
    }

    cb(null, payload, assertionParams);
  });
};