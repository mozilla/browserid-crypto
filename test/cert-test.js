/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var vows = require("vows"),
    assert = require("assert"),
    jwcrypto = require("../index"),
    assertion = jwcrypto.assertion,
    cert = jwcrypto.cert,
    testUtils= require("./utils");

var suite = vows.describe('cert');

testUtils.addBatches(suite, function(alg, keysize) {
  var keypair = null;
  return {
    "invocation of verifyBundle" : {
      topic: function() {
        var str = new String("bogus bundle");
        cert.verifyBundle(str, new Date(), function() {}, this.callback);
      },
      "fails as expected with a bogus string parameter": function(err, r) {
        assert.equal(err, "no certificates provided");
      }
    },
    "generate cert" : {
      topic: function() {
        var self = this;

        // generate a key
        jwcrypto.generateKeypair({algorithm: alg, keysize: keysize}, function(err, kp) {
          // stash it away
          keypair = kp;

          var assertionParams = {
            issuer : "issuer.com",
            issuedAt : new Date(),
            expiresAt : new Date((new Date()).getTime() + (6 * 60 * 60 * 1000))
          };

          // yes, we're signing our own public key, cause it's easier for now
          cert.sign({publicKey: keypair.publicKey, principal:{email: "john@issuer.com"}},
                    assertionParams, null, keypair.secretKey, self.callback);
        });
      },
      "cert is approximately proper format": function(err, signedObj) {
        assert.lengthOf(signedObj.split('.'), 3);
      },
      "verifying the cert using normal sig verify": {
        topic: function(signedObj) {
          jwcrypto.verify(signedObj, keypair.publicKey, this.callback);
        },
        "works out ok": function(err, payload) {
          assert.isNull(err);
          assert.isObject(payload);
        },
        "has right fields": function(err, payload) {
          assert.isString(payload.iss);
          assert.equal(payload.iss, "issuer.com");
          assert.isNumber(payload.iat);
          assert.isNumber(payload.exp);
          assert.isObject(payload.principal);
          assert.equal(payload.principal.email, "john@issuer.com");
        }
      },
      "verifying the cert using cert verify": {
        topic: function(signedObj) {
          // now is really now
          cert.verify(signedObj, keypair.publicKey, new Date(), this.callback);
        },
        "works out ok": function(err, payload, assertionParams, certParams) {
          assert.isNull(err);
          assert.isObject(payload);
          assert.isObject(assertionParams);
          assert.isObject(certParams);
        },
        "has right fields": function(err, payload, assertionParams, certParams) {
          assert.isString(assertionParams.issuer);
          assert.equal(assertionParams.issuer, "issuer.com");
          assert.isNotNull(assertionParams.issuedAt);
          assert.isNotNull(assertionParams.expiresAt);
          assert.isObject(certParams.principal);
          assert.isObject(certParams.publicKey);

          // make sure iss and exp are dates
          assert.isFunction(assertionParams.issuedAt.getFullYear);
          assert.isFunction(assertionParams.expiresAt.getFullYear);
          assert.equal(certParams.principal.email, "john@issuer.com");
        }
      }
    },
    "generate cert chain" : {
      topic: function() {
        var self = this;

        // expiration date
        var expiration = new Date(new Date().valueOf() + 120000);

        // once the cert chain is done, sign a 
        function signAssertion(rootPK, certs, user_keypair) {
          assertion.sign({}, {audience: "https://fakesite.com",
                              expiresAt: expiration},
                         user_keypair.secretKey,
                         function(err, signedAssertion) {
                           var bundle = cert.bundle(certs, signedAssertion);
                           self.callback(null, {
                             certs: certs,
                             bundle: bundle,
                             rootPK: rootPK,
                             userPK: user_keypair.publicKey
                           });
                         });
        }

        // generate three keypairs to chain things
        jwcrypto.generateKeypair({algorithm: alg, keysize: keysize}, function(err, root_kp) {
          jwcrypto.generateKeypair({algorithm: alg, keysize: keysize}, function(err, intermediate_kp) {
            jwcrypto.generateKeypair({algorithm: alg, keysize: keysize}, function(err, user_kp) {
              // generate the two certs
              cert.sign({publicKey: intermediate_kp.publicKey, principal: {host: "intermediate.root.com"}},
                        {issuer: "root.com", issuedAt: new Date(), expiresAt: expiration}, null,
                        root_kp.secretKey, function (err, signedIntermediate) {
                          cert.sign({publicKey: user_kp.publicKey, principal: {email: "john@root.com"}},
                                    {issuer: "intermediate.root.com", issuedAt: new Date(), expiresAt: expiration},
                                    null, intermediate_kp.secretKey,
                                    function(err, signedUser) {
                                      signAssertion(root_kp.publicKey,
                                                    [signedIntermediate, signedUser],
                                                    user_kp);
                                    });
                        });
            });
          });
        });
      },
      "proper root - just chain": {
        topic: function(stuff) {
          cert.verifyChain(stuff.certs, new Date(),
                            function(issuer, next) {
                              if (issuer == "root.com")
                                next(null, stuff.rootPK);
                              else
                                next("no root found");
                            },
                            this.callback
                           );
        },
        "verifies": function(err, certParamsArray) {
          assert.isNull(err);
          assert.isArray(certParamsArray);
        }
      },
      "proper root": {
        topic: function(stuff) {
          cert.verifyBundle(stuff.bundle, new Date(),
                            function(issuer, next) {
                              if (issuer == "root.com")
                                next(null, stuff.rootPK);
                              else
                                next("no root found");
                            },
                            this.callback
                           );
        },
        "verifies": function(err, certParamsArray, payload, assertionParams) {
          assert.isNull(err);
          assert.isArray(certParamsArray);
          assert.isObject(payload);
          assert.isObject(assertionParams);
          assert.isNotNull(assertionParams.audience);
        }
      },
      "improper root - just chain": {
        topic: function(stuff) {
          cert.verifyChain(stuff.certs, new Date(),
                            function(issuer, next) {
                              if (issuer == "root.com")
                                // wrong public key!
                                next(stuff.userPK);
                              else
                                next(null);
                            },
                            this.callback
                           );
        },
        "does not verify": function(err, certParamsArray) {
          assert.isNotNull(err);
          assert.isUndefined(certParamsArray);
        }
      },
      "improper root": {
        topic: function(stuff) {
          cert.verifyBundle(stuff.bundle, new Date(),
                            function(issuer, next) {
                              if (issuer == "root.com")
                                // wrong public key!
                                next(stuff.userPK);
                              else
                                next(null);
                            },
                            this.callback
                           );
        },
        "does not verify": function(err, certParamsArray, payload, assertionParams) {
          assert.isNotNull(err);
          assert.isUndefined(certParamsArray);
        }
      }
    },
    "null issued_at" : {
      topic: function() {
        var self = this;
        // generate a key
        jwcrypto.generateKeypair({algorithm: alg, keysize: keysize}, function(err, keypair) {
          var assertionParams = {
            issuer : "foo.com",
            issuedAt : null,
            expiresAt : new Date((new Date()).getTime() + (6 * 60 * 60 * 1000))
          };

          // yes, we're signing our own public key, cause it's easier for now
          cert.sign({publicKey: keypair.publicKey, principal: {email: "user@example.com"}},
                    assertionParams, null, keypair.secretKey, function(err, signedObj) {
                      cert.verify(signedObj, keypair.publicKey, new Date(), self.callback);
                    });
        });
      },
      "doesn't yield an erroneous date object": function(err, payload, assertionParams, certParams) {
        assert.isNull(assertionParams.issuedAt);
      }
    }
  };
});

// run or export the suite.
if (process.argv[1] === __filename) suite.run();
else suite.export(module);
