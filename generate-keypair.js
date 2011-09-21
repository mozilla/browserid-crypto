#!/usr/bin/env node

//
// generate a keypair quick
//

var jwk = require("./jwk"),
    fs = require("fs");

var args = require('optimist')
.usage('Generate an RSA keypair.\nUsage: $0', [ "foo" ])
.alias('h', 'help')
.describe('h', 'display this usage message')
.alias('k', 'keylength')
.describe('k', 'keylength, one of 64, 128, or 256.')
.default('k', 128);
var argv = args.argv;

if (argv.h) {
  args.showHelp();
  process.exit(1);
} else if (-1 === [ 64, 128, 256 ].indexOf(argv.k)) {
  console.log("invalid keylength:", argv.k);
  process.exit(1);
}


var keypair = jwk.KeyPair.generate("RS", argv.k);

fs.writeFileSync("key.publickey", keypair.publicKey.serialize());
fs.writeFileSync("key.secretkey", keypair.secretKey.serialize());
