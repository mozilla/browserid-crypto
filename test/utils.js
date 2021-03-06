/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * algorithms and utilities for executing tests on all of them
 */

// load up the right algorithms
var assert = require('assert');
require("../lib/algs/rs");
require("../lib/algs/ds");

var ALGORITHMS = {
  "RS": {
    alg: 'RS',
    keysizes: [64, 128, 256],
  },
  "DS": {
    alg: 'DS',
    keysizes: [128, 256]
  }
};

// add a batch that loops over algorithms and keysizes
exports.addBatches = function(suite, singleBatchMaker) {
  Object.keys(ALGORITHMS).forEach(function(algName) {
    ALGORITHMS[algName].keysizes.forEach(function(keysize) {
      var alg = ALGORITHMS[algName].alg;
      var batch = singleBatchMaker(alg, keysize);
      var overallBatch = {};
      overallBatch[alg + "/" + keysize] = batch;
      suite.addBatch(overallBatch);
    });
  });
};

exports.assertErr = function assertErr(err, type, message) {
  assert(type.prototype instanceof Error);
  assert(err instanceof type);
  assert.equal(err.message, message);
};
