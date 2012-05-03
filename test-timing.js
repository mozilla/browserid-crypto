#!/usr/bin/env node

//
// time test
//

var jwcrypto = require("./lib/jwcrypto");
require("./lib/algs/ds");
var libs = require("./libs/minimal");

function timeit(func_with_cb) {
  var start = new Date();
  func_with_cb(function() {
    var end = new Date();
    console.log(func_with_cb.toString() + " : " + (end-start));
  });
}

var rng = new libs.SecureRandom();

timeit(function(done) {jwcrypto.generateKeypair({algorithm:"DS", keysize: 256}, rng, done);});  

