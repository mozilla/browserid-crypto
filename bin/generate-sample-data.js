#!/usr/bin/env node

//
// generate a keypair quick
//

var jwcrypto = require("../index");
require("../lib/algs/ds");
require("../lib/algs/rs");

if (process.argv[2])
  jwcrypto.setDataFormatVersion(process.argv[2]);

var ISSUED_AT = new Date();
var EXPIRES_AT = new Date(new Date().valueOf() + 6000);
var ISSUER = "exampleidp.com";
var AUDIENCE = "https://example.com";
var EMAIL = "user@exampleidp.com";

// generate an RSA keypair
jwcrypto.generateKeypair(
  {algorithm: "RS", keysize: 256}, function(err, keypair) {
    // the public key
    console.log("ROOT RSA KEY");
    console.log(keypair.publicKey.serialize());

    console.log("ROOT RSA SECRET KEY");        
    console.log(keypair.secretKey.serialize());
    
    // the user keypair
    jwcrypto.generateKeypair(
      {algorithm: "DS", keysize: 128}, function(err, user_keypair) {
        console.log("USER DSA KEY");        
        console.log(user_keypair.publicKey.serialize());

        console.log("USER DSA SECRET KEY");        
        console.log(user_keypair.secretKey.serialize());
        
        // certify the user
        jwcrypto.cert.sign(
          {publicKey: user_keypair.publicKey, principal: {email: EMAIL}},
          {issuer: ISSUER, issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT},
          {}, keypair.secretKey,
          function(err, cert) {
            console.log("CERT");
            console.log(JSON.stringify({
              issued_at: ISSUED_AT.valueOf(),
              expires_at: EXPIRES_AT.valueOf(),
              issuer: ISSUER,
              email: EMAIL
            }));
            console.log(cert);

            jwcrypto.assertion.sign(
              {},
              {expiresAt: EXPIRES_AT, issuedAt: ISSUED_AT,
               audience: AUDIENCE},
              user_keypair.secretKey,
              function(err, assertion) {
                console.log(JSON.stringify({
                  issued_at: ISSUED_AT.valueOf(),
                  expires_at: EXPIRES_AT.valueOf(),
                  audience: AUDIENCE
                }));
                console.log("BACKED ASSERTION");
                console.log(jwcrypto.cert.bundle(cert, assertion));
              }
            );
          }
        )
      }
    );
  });

