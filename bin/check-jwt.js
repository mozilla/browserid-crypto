#!/usr/bin/env node

var vep = require("../vep"),
    jwt = require("../jwt"),
    jwcert = require("../jwcert");

var jwt_raw = process.argv[2];

var tok = new jwt.JWT();
tok.parse(jwt_raw);

console.log(tok);
