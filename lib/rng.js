/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * abstract out RNG depending on client or server.
 *
 * auto-seeding has to be requested.
 * (the seed is automatic, not the decision to auto-seed.)
 *
 * nextBytes takes a byteArray as input and populates it,
 * because that's how the cool kids do it and so we will not bikeshed.
 */

var utils = require("./utils"),
    delay = utils.delay,
    libs = require("../libs/minimal"),
    sjcl = libs.sjcl;

// detect if we have native crypto support
var crypto = null;
try {
  crypto = require("crypto");
} catch(e) {}

// proper boolean for whether we have native support
var IS_NATIVE = !!crypto;

function NativeRNG() {
}

NativeRNG.prototype = {
  addEntropy: function(seed_in) {
    // do nothing, natively we don't care
  },
  autoseed: function(cb) {
    // yay, don't need to do anything
    if (cb)
      delay(cb)();
  },
  nextBytes: function(byteArray) {
    var randomBytes = crypto.randomBytes(byteArray.length);
    for (var i=0; i<byteArray.length; i++)
      byteArray[i] = randomBytes[i];
  }
};

function BrowserRNG() {
}

BrowserRNG.prototype = {
  // WARNING: assumes that there's enough entropy in here to say it's 256
  addEntropy: function(seed_in) {
    sjcl.random.addEntropy(seed_in, 256);
  },
  autoseed: function(cb) {
    // see if we have window.crypto.getRandomValues
    if (window.crypto && window.crypto.getRandomValues) {
      // then sjcl already seeded itself
      if (cb)
        delay(cb)();
    } else {
      sjcl.random.addEventListener('seeded', function(blarg) {
        // no passing of arguments to the callback
        if (cb)
          cb();
      });

      // tell sjcl to start collecting some entropy      
      sjcl.random.startCollectors();
    }
  },
  nextBytes: function(byteArray) {
    var randomBytes = sjcl.random.randomWords(byteArray.length);
    for (var i=0; i<byteArray.length; i++)
      byteArray[i] = randomBytes[i];
  }
};

exports.RNG = IS_NATIVE ? NativeRNG : BrowserRNG;
