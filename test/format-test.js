#!/usr/bin/env node
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var
vows = require('vows'),
assert = require('assert'),
path = require('path'),
jwcrypto = require('../index'),
utils = require('../lib/utils'),
testUtils = require('./utils');

var suite = vows.describe('Format Tests');

var domainKeypair;
var userKeypair;

suite.addBatch({
  "generate a keypair": {
    topic: function() {
      jwcrypto.generateKeypair({algorithm: "RS", keysize: 256}, this.callback)
    },
    "works" : function(err, kp) {
      assert.isNull(err);
      domainKeypair = kp;
    }
  }
});

suite.addBatch({
  "generate a keypair": {
    topic: function() {
      jwcrypto.generateKeypair({algorithm: "DS", keysize: 128}, this.callback)
    },
    "works" : function(err, kp) {
      assert.isNull(err);
      userKeypair = kp;
    }
  }
});

// this function (jwcrypto.extractComponents) is copied here so that
// a change in the library doesn't mess up these conformance tests.
function extractComponents(signedObject) {
  if (typeof(signedObject) != 'string')
    throw "malformed signature " + typeof(signedObject);

  var parts = signedObject.split(".");
  if (parts.length != 3) {
    throw "signed object must have three parts, this one has " + parts.length;
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

var AUDIENCE = "http://foobar.com";
var ISSUER = "issuer.com";
var EMAIL = "john@example.com";

var now = new Date();
var in_a_minute = new Date(new Date().valueOf() + 60000);

suite.addBatch({
  "sign an assertion": {
    topic: function() {
      jwcrypto.assertion.sign({}, {expiresAt: in_a_minute, audience: AUDIENCE},
                              userKeypair.secretKey, this.callback);
    },
    "works" : function(err, signedObject) {
      assert.isNull(err);
    },
    "has three part": function(err, signedObject) {
      assert.equal(signedObject.split(".").length, 3);
    },
    "and then parsed": {
      topic: function(signedObject) {
        return extractComponents(signedObject);
      },
      "has proper header": function(components) {
        assert.isObject(components.header);
        assert.equal(components.header.alg, 'DS128');
        assert.equal(Object.keys(components.header).length, 1);
      },
      "has proper payload": function(components) {
        assert.isObject(components.payload);
        assert.equal(components.payload.exp, in_a_minute.valueOf());
        assert.equal(components.payload.aud, AUDIENCE);

        // optionally a version

        // nothing else
        assert.ok(Object.keys(components.payload).length <= 3);
        assert.ok(Object.keys(components.payload).length >= 2);
      },
      "has proper signature": function(components) {
        assert.isString(components.signature);

        // 160 bits for r and s, 320 bits together, 80 hex chars
        // but because of encoding, leading 0s may have gotten removed
        // likelihood of X zeros, 1/(2^(4X))
        // let's allow for up to 5 zeros.
        assert.ok(components.signature.length <= 80);
        assert.ok(components.signature.length > 75);
      }
    }
  }
});

suite.addBatch({
  "sign a cert": {
    topic: function() {
      jwcrypto.cert.sign({publicKey: userKeypair.publicKey, principal: {email: EMAIL}},
                         {issuedAt: now, issuer: ISSUER, expiresAt: in_a_minute},
                         {},
                         domainKeypair.secretKey, this.callback);
    },
    "works" : function(err, signedObject) {
      assert.isNull(err);
    },
    "has three parts": function(err, signedObject) {
      assert.equal(signedObject.split(".").length, 3);
    },
    "and then parsed": {
      topic: function(signedObject) {
        return extractComponents(signedObject);
      },
      "has proper header": function(components) {
        assert.isObject(components.header);
        assert.equal(components.header.alg, 'RS256');
        assert.equal(Object.keys(components.header).length, 1);
      },
      "has proper payload": function(components) {
        assert.isObject(components.payload);
        assert.equal(components.payload.iss, ISSUER);
        assert.equal(components.payload.exp, in_a_minute.valueOf());
        assert.equal(components.payload.iat, now.valueOf());

        assert.isObject(components.payload.principal);
        assert.equal(components.payload.principal.email, EMAIL);
        assert.equal(Object.keys(components.payload.principal).length, 1);

        // assert.equal(JSON.stringify(components.payload.publicKey), userKeypair.publicKey.serialize());
        assert.equal(JSON.stringify(components.payload['public-key']), userKeypair.publicKey.serialize());

        // optionally version

        // nothing else
        assert.ok(Object.keys(components.payload).length <= 6);
        assert.ok(Object.keys(components.payload).length >= 5);
      },
      "has proper signature": function(components) {
        assert.isString(components.signature);

        // 2048 bits = 512 hex chars, but could be less. Though very unlikely
        // to be less than 32 bits less :)
        assert.ok(480 < components.signature.length);
        assert.ok(components.signature.length <= 512);
      }
    }
  }
});

// run or export the suite.
if (process.argv[1] === __filename) suite.run();
else suite.export(module);
