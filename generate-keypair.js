//
// generate a keypair quick
//

var jws = require("./jws"),
    fs = require("fs");

var keypair = jws.getByAlg("RS").KeyPair.generate(64);
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