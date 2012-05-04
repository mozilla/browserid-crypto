JavaScript implementation of JSON Web Signatures and JSON Web Tokens, especially as needed by BrowserID.

- libs contains third-party libraries that need to be included. See
libs/dependencies.txt and libs/package.txt

- This is written as CommonJS modules for node and
  such. Browserify is used to bundle it all up.

NOTE: this is written as future documentation of v0.2 APIs, which will not
be backwards compatible with v0.1.

Overview
===

JSON Web Tokens (JWTs) look like:

    eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
    .
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
    .
    dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

(line breaks are for readability)

JWTs are made up of three components, each base64url-encoded, joined by a period character. A JWT can be either a JWS (JSON Web Signature) or a JWE (JSON Web Encryption). In this library, we only consider JWS. Because JWT is effectively the abstract superclass of both JWS and JWE, we don't expose JWT APIs directly (as of v0.2.0). We simply expose a JWS API.

We use JWK (JSON Web Keys) to specify keys:
http://tools.ietf.org/html/draft-ietf-jose-json-web-key-00

We use JWA (JSON Web Algorithms) to specify algorithms:
http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-00
(we add algorithm "DS" to indicate DSA, with DS160 the standard DSA 1024/160.)

Basic API
=========

    var jwcrypto = require("jwcrypto");

    // random number generation is taken care of automatically.
    // more entropy can be added as follows
    // entropy should be either a 32 bit int, an array of ints, or a string
    jwcrypto.addEntropy(entropy);

    // generate a key
    // we use DSA, which is "DS" in JSON Web Algorithm parlance
    // we use keysize 160, which has a specific interpretation based
    // on the algorithm, in this case DSA 1024/160, standard DSA.
    jwcrypto.generateKeypair({
        algorithm: 'DS',
        keysize: 160
    }, function(err, keypair) {
        // error in err?

        // serialize the public key
        console.log(keypair.publicKey.toString());

        // just the JSON object to embed in another structure
        console.log(JSON.stringify({stuff: keypair.publicKey.toJSONObject()}));

        // create and sign a JWS
        var payload = {principal: {email: 'some@dude.domain'},
                       pubkey: jwcrypto.loadPublicKey(publicKeyToCertify)};

        jwcrypto.sign(payload, keypair.secretKey, function(err, jws) {
           // error in err?

           // serialize it
           console.log(jws.toString());
        });

        // also, if loading a secret key from somewhere
        // note how JWK determines automatically if it's a secret key
        // or public key. XXX should this be more explicit?
        var otherSecretKey = jwcrypto.loadSecretKey(storedSecretKey);

        // verify it
        jwcrypto.verify(signedObject, publicKey, function(err, payload) {
          // if verification fails, then err tells you why
          // if verification succeeds, err is null, and payload is
          // the signed JS object.
        });
    });

Assertions
====

Sometimes the JSON object to sign should be a standard assertion with pre-defined fields.

    var assertion = require("jwcrypto").assertion;

    // payload of the assertion
    var payload = {principal: {email: 'some@dude.domain'}};

    // add special fields which will be encoded properly
    // payload cannot contain reserved fields
    assertion.sign(payload, {issuer: "foo.com", expiresAt: new Date(),
                             issuedAt: new Date(), audience: "https://example.com"},
                      keypair.secretKey,
                      function(err, signedAssertion) {
       // a normal signedObject, much like above
       // can be verified with jwcrypto.verify

       // or verified specifically for jwt, with expiration verification
       var now = new Date();
       assertion.verify(signedObject, keypair.publicKey, now, function(err, payload, assertionParams) {
          // payload is the original payload
          // assertionParams contains issuedAt, expiresAt as dates
          // and issuer and audience as strings.
       });
    });


Certs
=======

Sometimes the JSON objects to sign are certificates

    var cert = require("jwcrypto").cert;

    var keyToCertify = keypairToCertify.publicKey;
    var principal = {email: "someone@example.com"};
    var assertionParams = {issuer: "foo.com", issuedAt: new Date(),
                           expiresAt: new Date()};
    var additionalPayload = {};

    // payload cannot contain reserved fields
    cert.sign(keyToCertify, principal,
                assertionParams, additionalPayload,
                keypair.secretKey,
                function(err, signedObject) {
       // normal signedObject
       // can be verified with jwcrypto.verify

       // or verified specifically for certification
       // include a date that is considered the "now"
       cert.verify(signedObject, keypair.publicKey, now, function(err, payload, assertionParams, certParams) {
          // the extra payload
          // the assertionParams specifics
          // the certParams include publicKey being certified, and principal bound to it.
       });
    });

    // bundle a cert chain and an assertion
    var bundle = cert.bundle([certs], assertion);

    function getPK(issuer, next) {
        // function to get a public key for an issuer
    }

    var now = new Date();

    // verify just the chain of certs
    cert.verifyChain([certs], now, getPK, function(err, certParamsArray) {
       // err is an error or null
       // if no error:
       // certParamsArray is the array of individual cert params from each verification
       // including specifically the publicKey and principal parameters
    });

    // verify a chain of certs and assertion
    cert.verifyBundle(bundle, now, getPK, function(err, certParamsArray, payload, assertionParams) {
       // err is an error or null
       // if no error:
       // certParamsArray is the array of individual cert params from each verification
       // payload is the assertion payload, and assertionParams is the assertion params.
    });