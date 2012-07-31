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

var suite = vows.describe('API tests');

// disable vows (often flakey?) async error behavior
suite.options.error = false;

suite.addBatch({
  "adding entropy": {
    topic: function() {
      jwcrypto.addEntropy("foobarbaz");
      return null;
    },
    "works": function() {
      assert.ok(true);
    }
  }
});

function mungePayload(signedObject) {
    var p = jwcrypto.extractComponents(signedObject);
    var payload = p.payload;
    payload.evilNewField = "evil";
    var newPayloadSegment = utils.base64urlencode(JSON.stringify(payload));
    return p.headerSegment+"."+newPayloadSegment+"."+p.cryptoSegment;
}

testUtils.addBatches(suite, function(alg, keysize) {
  var keypair;
  var obj = {foo: "bar"};
  return {
    "generation of a keypair" : {
      topic: function() {
        jwcrypto.generateKeypair({
          algorithm: alg,
          keysize: keysize
        }, this.callback);
      },
      "produces something that looks right": function(err, kp) {
        assert.equal(err, null);
        assert.isObject(kp);
        assert.isObject(kp.secretKey);
        assert.isObject(kp.publicKey);
        keypair = kp;
      },
      "produces a keypair with right params": function(err, kp) {
        assert.equal(kp.algorithm, alg);
        assert.equal(kp.keysize, keysize);
      },
      "secret key": {
        topic: function() {
          return keypair.secretKey;
        },
        "has algorithm": function(sk) {
          assert.isString(sk.algorithm);
        },
        "can be serialized": function(sk) {
          assert.isString(sk.serialize());
        },
        "can be reloaded": function(sk) {
          assert.isObject(jwcrypto.loadSecretKey(sk.serialize()));
        },
        "reloaded equals the original": function(sk) {
          // XXX - do string compare on serialized items, not quite right
          assert.equal(sk.serialize(), jwcrypto.loadSecretKey(sk.serialize()).serialize());
        }
      },
      "public key": {
        topic: function() {
          return keypair.publicKey;
        },
        "has algorithm": function(pk) {
          assert.isString(pk.algorithm);
        },
        "can be serialized": function(pk) {
          assert.isString(pk.serialize());
        },
        "can be reloaded": function(pk) {
          assert.isObject(jwcrypto.loadPublicKey(pk.serialize()));
        },
        "can be reloaded from object": function(pk) {
          assert.isObject(jwcrypto.loadPublicKeyFromObject(JSON.parse(pk.serialize())));
        },
        "reloaded equals the original": function(pk) {
          // XXX - do string compare on serialized items, not quite right
          assert.equal(pk.serialize(), jwcrypto.loadPublicKey(pk.serialize()).serialize());
        }
      },
      "signing" : {
        topic: function() {
          jwcrypto.sign(obj, keypair.secretKey, this.callback);
        },
        "works": function(err, signedObject) {
          assert.isNull(err);
          assert.isString(signedObject);
        },
        "verification" : {
          topic: function(err, signedObject) {
            jwcrypto.verify(signedObject, keypair.publicKey, this.callback);
          },
          "payload is the same": function(err, payload) {
            assert.equal(JSON.stringify(payload), JSON.stringify(obj));
          },
          "no error": function(err, payload) {
            assert.isNull(err);
          }
        },
        "munged": {
          topic: function(err, signedObject) {
            jwcrypto.verify(mungePayload(signedObject), keypair.publicKey, this.callback);
          },
          "errors": function(err, payload) {
            assert.isNotNull(err);
          },
          "no payload": function(err, payload) {
            assert.isUndefined(payload);
          }
        }
      },
      "signing with reserialized keys": {
        topic: function() {
          jwcrypto.sign(obj, jwcrypto.loadSecretKey(keypair.secretKey.serialize()),
                        this.callback);
        },
        "works": function(err, signedObject) {
          assert.isNull(err);
          assert.isString(signedObject);
        },
        "verification" : {
          topic: function(err, signedObject) {
            jwcrypto.verify(signedObject, jwcrypto.loadPublicKey(keypair.publicKey.serialize()),
                            this.callback);
          },
          "payload is the same": function(err, payload) {
            assert.equal(JSON.stringify(payload), JSON.stringify(obj));
          },
          "no error": function(err, payload) {
            assert.isNull(err);
          }
        },
        "munged": {
          topic: function(err, signedObject) {
            jwcrypto.verify(mungePayload(signedObject),
                            jwcrypto.loadPublicKey(keypair.publicKey.serialize()),
                            this.callback);
          },
          "errors": function(err, payload) {
            assert.isNotNull(err);
          },
          "no payload": function(err, payload) {
            assert.isUndefined(payload);
          }
        }
      }
    }
  };
});


// run or export the suite.
if (process.argv[1] === __filename) suite.run();
else suite.export(module);
