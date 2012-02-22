#!/usr/bin/env node

const
vows = require('vows'),
assert = require('assert'),
path = require('path'),
jwcrypto = require('../api.js');

var suite = vows.describe('external API testts');

// disable vows (often flakey?) async error behavior
suite.options.error = false;

var keypair_rsa, keypair_dsa;

suite.addBatch({
  "generation of a DSA keypair": {
    topic: function() {
      jwcrypto.generateKeypair({
        bits: 256,
        algorithm: 'dsa'
      }, this.callback);
    },
    "works": function(err, r) {
      assert.equal(err, null);
      assert.isObject(r);
      assert.isObject(r.secretKey);
      assert.isObject(r.publicKey);
      keypair_dsa = r;
    }
  }
});

suite.addBatch({
  "generation of an RSA keypair": {
    topic: function() {
      jwcrypto.generateKeypair({
        bits: 128,
        algorithm: 'rsa'
      }, this.callback);
    },
    "works": function(err, r) {
      assert.isNull(err);
      assert.isObject(r);
      assert.isObject(r.secretKey);
      assert.isObject(r.publicKey);
      keypair_rsa = r;
    }
  }
});

var cert = undefined;

// a test which excercises certificate generation
suite.addBatch({
  "signing the DSA pubkey into a JWS": {
    topic: function() {
      jwcrypto.JWS.create({
        email: 'some@dude.domain',
        pubkey: keypair_dsa.publicKey.serialize()
      }, keypair_rsa.secretKey, this.callback);
    },
    "succeeds without error": function(err, r) {
      console.log("err", err, "r", r);
      assert.isNull(err);
      assert.isObject(r);
      cert = r;
    },
    "and the payload of that JWS": {
      topic: function(err, r) {
        return r ? r.payload() : null;
      },
      "is well-formed": function(payload) {
        assert.isObject(payload);
        console.log(payload);
      }
    }
  }
});
  
// XXX: test our ability to specify reserved fields from
// the client.

// run or export the suite.
if (process.argv[1] === __filename) suite.run();
else suite.export(module);
