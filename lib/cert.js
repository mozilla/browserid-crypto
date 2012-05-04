/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var jwcrypto = require("./jwcrypto"),
    assertion = require("./assertion"),
    utils = require("./utils"),
    delay = utils.delay,
    und = require("./underscore.js");

exports.sign = function(publicKeyToSign, principal,
                        assertionParams, additionalPayload,
                        secretKey, cb) {
  var payload = {};
  utils.copyInto(additionalPayload || {}, payload);
  payload['public-key'] = publicKeyToSign.toSimpleObject();
  payload.principal = principal;

  assertion.sign(payload, assertionParams, secretKey, cb);
};

var verify = function(signedObject, publicKey, now, cb) {
  assertion.verify(signedObject, publicKey, now, function(err, payload, assertionParams) {
    if (err)
      return cb(err);

    // compatible with old format
    var publicKey = jwcrypto.loadPublicKey(JSON.stringify(payload['public-key']));
    delete payload['public-key'];
    var principal = payload.principal;
    delete payload.principal;
    cb(err, payload, assertionParams, {principal: principal, 'public-key': publicKey});
  });
};

exports.verify = verify;

exports.bundle = function(certs, signedAssertion) {
  if (!certs || certs.length == 0)
    throw "certificates must be a non-empty array";
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
    return delay(cb)("certs must be an array of at least one cert");

  var rootIssuer;
  try {
    // the root
    rootIssuer = jwcrypto.extractComponents(certs[0]).payload.iss;
  } catch (x) {
    // can't extract components
    return delay(cb)("malformed signature");
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
        cb(null, certParamsArray, certParams['public-key']);
      else
        delay(verifyCert)(i, certParams['public-key'], certParamsArray, cb);
    });
  }
  
  // get the root public key
  getRoot(rootIssuer, function(err, rootPK) {
    if (err) return delay(cb)(err);

    verifyCert(0, rootPK, [], function(err, certParamsArray, lastPK) {
      if (err) return cb(err);

      // we're done
      cb(null, certParamsArray);
    });
    
  });    
  
};

exports.verifyChain = verifyChain;

exports.verifyBundle = function(bundle, now, getRoot, cb) {
  // unbundle
  if (typeof(bundle) != 'string')
    return delay(cb)("malformed backed assertion");

  var parsedBundle = exports.unbundle(bundle);
  var signedAssertion = parsedBundle.signedAssertion;
  var certs = parsedBundle.certs;

  // no certs? not okay
  if (certs.length == 0)
    return delay(cb)("no certificates provided");

  // verify the chain
  verifyChain(certs, now, getRoot, function(err, certParamsArray) {
    // simplify error message
    if (err) {
      // allow through the malformed signature
      if (err == 'malformed signature' ||
          err == "assertion issued later than verification date" ||
          err == "assertion has expired")
        return cb(err);
      else
        return cb("bad signature in chain");
    }

    // what was the last PK in the successful chain?
    var lastPK = certParamsArray[certParamsArray.length - 1].certParams['public-key'];
    
    // now verify the assertion
    assertion.verify(signedAssertion, lastPK, now, function(err, payload, assertionParams) {
      if (err) return cb(err);
      
      // we're good!
      cb(null, certParamsArray, payload, assertionParams);
    });
  });
};
