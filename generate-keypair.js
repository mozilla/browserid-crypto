//
// generate a keypair quick
//

var jwk = require("./jwk"),
    fs = require("fs");

var keypair = jwk.KeyPair.generate("RS",64);

fs.writeFileSync("key.publickey", keypair.publicKey.serialize());
fs.writeFileSync("key.secretkey", keypair.secretKey.serialize());