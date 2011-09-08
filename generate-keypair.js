//
// generate a keypair quick
//

var jwk = require("./jwk"),
    fs = require("fs");

var keypair = jwk.KeyPair.generate("RS",64);
var pk = {
  alg: "RS",
  value: keypair.publicKey.serialize()
};

var sk = {
  alg: "RS",
  value: keypair.secretKey.serialize()
};

fs.writeFileSync("key.publickey", JSON.stringify(pk));
fs.writeFileSync("key.secretkey", JSON.stringify(sk));