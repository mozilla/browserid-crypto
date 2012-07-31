#!/usr/bin/env node
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var
vows = require('vows'),
assert = require('assert'),
rng = require('../lib/rng');

var suite = vows.describe('RNG tests');

suite.addBatch({
  "create rng": {
    topic: function() {
      return new rng.RNG();
    },
    "looks good": function(rng) {
      assert.isObject(rng);
      assert.isFunction(rng.addEntropy);
      assert.isFunction(rng.autoseed);
      assert.isFunction(rng.nextBytes);
    },
    "and when we seed": {
      topic: function(rng) {
        rng.addEntropy("foobar");
        return null;
      },
      "all is well": function() {
        assert.ok(true);
      }
    },
    "and when we autoseed": {
      topic: function(rng) {
        rng.autoseed(this.callback);
      },
      "eventually returns": function() {
        assert.ok(true);
      },
      "and when we get random bytes": {
        topic: function(rng) {
          var bytes = [0,0,0,0,0,0,0,0,0,0];
          rng.nextBytes(bytes);
          return bytes;
        },
        "contains stuff": function(bytes) {
          assert.isArray(bytes);
        },
        "and that stuff is random'ish": function(bytes) {
          // this test is unlikely to fail unless no randomness is getting out
          assert.ok(!(bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0));
        }
      }
    },
  }
});
// run or export the suite.
if (process.argv[1] === __filename) suite.run();
else suite.export(module);
