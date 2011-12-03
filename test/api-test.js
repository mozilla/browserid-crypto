#!/usr/bin/env node

const
vows = require('vows'),
assert = require('assert'),
path = require('path'),
jwcrypto = require('../api.js');

var suite = vows.describe('external API testts');

// disable vows (often flakey?) async error behavior
suite.options.error = false;

suite.addBatch({
  "generation of a keypair": {
    topic: function() {
      jwcrypto.generateKeypair({
        bits: 256,
        algorithm: 'dsa'
      }, this.callback);
    },
    "works": function(err, r) {
      assert.equal(err, null);
      assert.isObject(r);
    }
  }
});



// run or export the suite.
if (process.argv[1] === __filename) suite.run();
else suite.export(module);
