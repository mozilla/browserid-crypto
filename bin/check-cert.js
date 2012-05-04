#!/usr/bin/env node

var jwcrypto = require("../index");

var cert_raw = process.argv[2];
var pk_raw = process.argv[3];

var cert = jwcrypto.extractComponents(cert_raw);
console.log("issuer: " + cert.payload.iss);
console.log("full payload: " + JSON.stringify(cert.payload));
console.log("principal:" + JSON.stringify(cert.payload.principal));
console.log("key:" + cert.payload['public-key'].serialize());
console.log("expiration:" + cert.payload.exp);

var pk = jwcrypto.loadPublicKey(pk_raw);

console.log("verifying the raw signature - no cert specific verification");

jwcrypto.verify(cert, pk, function(err, payload) {
  if (err) {
    console.log("doesn't work");
    console.log(err);
  } else{
    console.log("works");
  }
});
