#!/usr/bin/env node

var
fs = require('fs'),
jwcrypto = require("../index");

// Side effects Issue #24
require("../lib/algs/ds");
require("../lib/algs/rs");

var args = require('optimist')
.usage('Check certificate\nUsage: $0')
.alias('p', 'public')
.describe('p', 'public key to sign')
.demand('p')
.alias('h', 'help')
.describe('h', 'display this usage message')
.alias('c', 'certificate')
.describe('c', 'A certificate which you want to examine.')
.demand('c')
.alias('d', 'debug')
.describe('d', 'Debug mode, useful for development of this tool')
.boolean('d')
.default('d', false);

var argv = args.argv;

if (argv.h) {
  args.showHelp();
  process.exit(1);
}

var debug = argv.d;

if (debug) console.log('Reading cert file=', argv.c);
var cert_raw = fs.readFileSync(argv.c).toString('utf8');

var cert = jwcrypto.extractComponents(cert_raw);

console.log("issuer: " + cert.payload.iss);
console.log("full payload: " + JSON.stringify(cert.payload));
console.log("principal:" + JSON.stringify(cert.payload.principal));
console.log("key:" + JSON.stringify(cert.payload['public-key'], null, 4));
console.log("expiration:" + cert.payload.exp);

if (debug) console.log('Reading public file=', argv.p);
var pk_raw = fs.readFileSync(argv.p).toString('utf8');


var pk = jwcrypto.loadPublicKey(pk_raw);
if (debug) console.log(JSON.stringify(JSON.parse(pk.serialize()), null, 4));

console.log("verifying the raw signature - no cert specific verification");

jwcrypto.verify(cert_raw, pk, function(err, payload) {
  if (err) {
    console.log("doesn't work");
    console.log(err);
  } else{
    console.log("works");
  }
});
