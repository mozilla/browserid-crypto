#!/usr/bin/env node

var vep = require("../vep"),
    jwt = require("../jwt"),
    jwcert = require("../jwcert"),
    jwk = require("../jwk");

var cert_raw = process.argv[2];
var pk_raw = process.argv[3];

var cert = new jwcert.JWCert();
cert.parse(cert_raw);
console.log("issuer: " + cert.issuer);
console.log("full payload: " + cert.serializePayload());
console.log("principal:" + JSON.stringify(cert.principal));
console.log("key:" + cert.pk.serialize());
console.log("expiration:" + cert.expires);

var pk_obj = JSON.parse(pk_raw);
var pk = jwk.PublicKey.fromSimpleObject(pk_obj);

console.log("works? " + cert.verify(pk));
