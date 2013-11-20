/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var vows = require("vows"),
    assert = require("assert"),
    jwcrypto = require("../index"),
    assertion = jwcrypto.assertion,
    utils = require("../lib/utils"),
    testUtils = require('./utils');

var suite = vows.describe('assertion');

var payload = {
  foo: "bar"
};

var now = new Date();
var in_a_minute = new Date(now.getTime() + (60 * 1000));
var a_second_ago = new Date(now.getTime() - 1000);

testUtils.addBatches(suite, function(alg, keysize) {
  return {
    "generate keypair" : {
      topic: function() {
        jwcrypto.generateKeypair(
          {algorithm: alg, keysize: keysize},
          this.callback);
      },
      "looks good": function(err, kp) {
        assert.isNull(err);
      },
      "sign an assertion": {
        topic: function(kp) {
          assertion.sign(payload, {issuer: "foo.com", expiresAt: in_a_minute,
                                   audience: "https://example.com"},
                         kp.secretKey,
                         this.callback);
        },
        "works": function(err, signedObject) {
          assert.isNull(err);
          assert.isString(signedObject);
        },
        "has approximately right format": function(err, signedObject) {
          assert.lengthOf(signedObject.split('.'), 3);
        },
        "when verified": {
          topic: function(signedObject, kp) {
            jwcrypto.verify(signedObject, kp.publicKey, this.callback);
          },
          "works": function(err, payload) {
            assert.isNull(err);
            assert.isObject(payload);
          },
          "returns payload with all expected fields": function(err, payload) {
            assert.isNotNull(payload.foo);
            assert.isNotNull(payload.exp);
            assert.isNotNull(payload.iss);
            assert.isNotNull(payload.aud);
            assert.equal(payload.aud, "https://example.com");
            assert.equal(payload.exp, in_a_minute.valueOf());
          }
        },
        "when verified with assertion": {
          topic: function(signedObject, kp) {
            // now is Date()
            assertion.verify(signedObject, kp.publicKey, now, this.callback);
          },
          "works": function(err, payload, assertionParams) {
            assert.isNull(err);
            assert.isObject(payload);
            assert.isObject(assertionParams);
          },
          "has right payload": function(err, newPayload, assertionParams) {
            assert.equal(JSON.stringify(payload), JSON.stringify(newPayload));
          },
          "assertionparams is good": function(err, newPayload, assertionParams) {
            assert.isNotNull(assertionParams.expiresAt);
            assert.isNotNull(assertionParams.issuer);
            assert.isNotNull(assertionParams.audience);
            assert.equal(assertionParams.audience, "https://example.com");
            assert.equal(assertionParams.expiresAt.valueOf(), in_a_minute.valueOf());
          }
        }
      },
      "sign an assertion that is already expired": {
        topic: function(kp) {
          assertion.sign(payload, {issuer: "foo.com", expiresAt: a_second_ago,
                                  audience: "https://example.com"},
                         kp.secretKey,
                         this.callback);
        },
        "works": function(err, signedObject) {
          assert.isNull(err);
          assert.isString(signedObject);
        },
        "has approximately right format": function(err, signedObject) {
          assert.lengthOf(signedObject.split('.'), 3);
        },
        "when verified": {
          topic: function(signedObject, kp) {
            jwcrypto.verify(signedObject, kp.publicKey, this.callback);
          },
          "works": function(err, payload) {
            assert.isNull(err);
            assert.isObject(payload);
          },
          "returns payload with all expected fields": function(err, payload) {
            assert.isNotNull(payload.foo);
            assert.isNotNull(payload.exp);
            assert.isNotNull(payload.iss);
            assert.isNotNull(payload.aud);
            assert.equal(payload.aud, "https://example.com");
            assert.equal(payload.exp, a_second_ago.valueOf());
          }
        },
        "when verified with assertion": {
          topic: function(signedObject, kp) {
            // now is Date()
            assertion.verify(signedObject, kp.publicKey, new Date(), this.callback);
          },
          "does not verify": function(err, payload, assertionParams) {
            assert.isString(err);
            assert.isUndefined(payload);
          },
          "returns the right error message": function(err, payload, assertionParams) {
            assert.equal(err, "expired");
          }
        }
      },
      "sign an assertion issued in the future": {
        topic: function(kp) {
          assertion.sign(payload, {issuer: "foo.com", issuedAt: in_a_minute, expiresAt: in_a_minute},
                         kp.secretKey,
                         this.callback);
        },
        "works": function(err, signedObject) {
          assert.isNull(err);
          assert.isString(signedObject);
        },
        "has approximately right format": function(err, signedObject) {
          assert.lengthOf(signedObject.split('.'), 3);
        },
        "when verified": {
          topic: function(signedObject, kp) {
            jwcrypto.verify(signedObject, kp.publicKey, this.callback);
          },
          "works": function(err, payload) {
            assert.isNull(err);
            assert.isObject(payload);
          },
          "returns payload with all expected fields": function(err, payload) {
            assert.isNotNull(payload.foo);
            assert.isNotNull(payload.exp);
            assert.isNotNull(payload.iat);
            assert.isNotNull(payload.iss);
            assert.isUndefined(payload.aud);
            assert.equal(payload.exp, in_a_minute.valueOf());
            assert.equal(payload.iat, in_a_minute.valueOf());
          }
        },
        "when verified with assertion": {
          topic: function(signedObject, kp) {
            // now is Date()
            assertion.verify(signedObject, kp.publicKey, new Date(), this.callback);
          },
          "does not verify": function(err, payload, assertionParams) {
            assert.isString(err);
            assert.isUndefined(payload);
          },
          "returns the right error message": function(err, payload, assertionParams) {
            assert.equal(err, "issued later than verification date");
          }
        }
      }
    }
  };
});


// run or export the suite.
if (process.argv[1] === __filename) suite.run();
else suite.export(module);
