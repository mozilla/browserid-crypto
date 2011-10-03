#!/usr/bin/env node

//
// time test
//

var jwk = require("./jwk");

function timeit(stuff, n_times) {
  var start = new Date();
  for (var i=0; i<n_times; i++)
    stuff();
  var end = new Date();
  console.log(n_times + " x : " + stuff.toString() + " : " + (end-start));
}

timeit(function() {jwk.KeyPair.generate("DS", 256);}, 10);  

var kp = jwk.KeyPair.generate("DS", 256);

timeit(function() {kp.secretKey.sign("foobar!!!!!");}, 10);

var signature = kp.secretKey.sign("foobar!!!!!");

timeit(function() {kp.publicKey.verify("foobar!!!!!", signature);}, 10);
