/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var vows = require("vows"),
    assert = require("assert"),
    utils = require("../lib/utils");

var VALUES_TO_TEST = [
  "ea63db6501ecd889e999ce1b8bcd7102b3ed741be91cb036423066f99ab0063fd42e7c242717674d931320f9a4bd5e98a969d44c0e3bd2f6aad005e88108ce5"
  ];

vows.describe('utils').addBatch(
  {
    "b64url encoding and decoding" : {
      topic: function() {
        var encoded = utils.hex2b64urlencode(VALUES_TO_TEST[0]);
        var decoded = utils.b64urltohex(encoded);
        return decoded;
      },
      
      "proper decoding": function(result) {
        assert.equal(result, VALUES_TO_TEST[0]);
      }
    }
}).export(module);