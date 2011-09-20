#!/usr/bin/env node

//
// generate a keypair quick
//

var jwk = require("./jwk"),
    fs = require("fs");

var keypair = jwk.KeyPair.generate("RS",128);

fs.writeFileSync("key.publickey", keypair.publicKey.serialize());
fs.writeFileSync("key.secretkey", keypair.secretKey.serialize());