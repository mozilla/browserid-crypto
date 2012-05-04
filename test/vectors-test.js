/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

var vows = require("vows"),
    assert = require("assert"),
    utils = require("../lib/utils"),
    jwcrypto = require("../index");

require("../lib/algs/rs");
require("../lib/algs/ds");

var VECTORS = [
  {
    assertion: "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjcuMC4wLjEiLCJleHAiOjEzMzU1NjI2OTg3NjgsImlhdCI6MTMzNTU1OTA5ODc2OCwicHVibGljLWtleSI6eyJhbGdvcml0aG0iOiJEUyIsInkiOiIyN2Y2OTgzMWIzNzdlMmY1NzRiZGE5Njg1YWJmNTM5OTY1ZDAyNDI2Mjg0ZDZmYzViOWVkMjA0MzJmN2U5Yjg1YTFjMjJiMTQ2M2I0NmQwMzljMTIzOWJkZWI2NDc1ZDZjMDM0MWJlZmRiYzBjYjJmMjQ4MTUzYjRjMzFkZDMxNWFjZjFkZmY0ZWUwYmY2NGY4OTUyN2VlMTlmNTkxNTM3NWFjZTNkNTZjMWQ1NDUzY2FjNmRkMTE4NzU3NTI3MmRhYjBlZGQzMGYxYjRlOTI2Yzg3YTNlNGFjYWY2NmY5MmZlZDFhMDRhYjI3Y2NjNDkxM2FmZTI0ZGRjZjNmZTk4IiwicCI6ImZmNjAwNDgzZGI2YWJmYzViNDVlYWI3ODU5NGIzNTMzZDU1MGQ5ZjFiZjJhOTkyYTdhOGRhYTZkYzM0ZjgwNDVhZDRlNmUwYzQyOWQzMzRlZWVhYWVmZDdlMjNkNDgxMGJlMDBlNGNjMTQ5MmNiYTMyNWJhODFmZjJkNWE1YjMwNWE4ZDE3ZWIzYmY0YTA2YTM0OWQzOTJlMDBkMzI5NzQ0YTUxNzkzODAzNDRlODJhMThjNDc5MzM0MzhmODkxZTIyYWVlZjgxMmQ2OWM4Zjc1ZTMyNmNiNzBlYTAwMGMzZjc3NmRmZGJkNjA0NjM4YzJlZjcxN2ZjMjZkMDJlMTciLCJxIjoiZTIxZTA0ZjkxMWQxZWQ3OTkxMDA4ZWNhYWIzYmY3NzU5ODQzMDljMyIsImciOiJjNTJhNGEwZmYzYjdlNjFmZGYxODY3Y2U4NDEzODM2OWE2MTU0ZjRhZmE5Mjk2NmUzYzgyN2UyNWNmYTZjZjUwOGI5MGU1ZGU0MTllMTMzN2UwN2EyZTllMmEzY2Q1ZGVhNzA0ZDE3NWY4ZWJmNmFmMzk3ZDY5ZTExMGI5NmFmYjE3YzdhMDMyNTkzMjllNDgyOWIwZDAzYmJjNzg5NmIxNWI0YWRlNTNlMTMwODU4Y2MzNGQ5NjI2OWFhODkwNDFmNDA5MTM2YzcyNDJhMzg4OTVjOWQ1YmNjYWQ0ZjM4OWFmMWQ3YTRiZDEzOThiZDA3MmRmZmE4OTYyMzMzOTdhIn0sInByaW5jaXBhbCI6eyJlbWFpbCI6ImJlbkBhZGlkYS5uZXQifX0.MklRRWfQweUwYR2crhFU2EuLyUOZlpY4zJgg9LSWDF1MQIGJtNZAclB_tU4sNWfWyrHBa6ICXGfT9mMbkWwPIZC714clAkCMAQXiL2FhuzZSHlnYRO0_BFLO0LqtxIbwdGAQ0WvmaS5lPCgwHdoJbIHPVupebT1C-nUUu21pBoFI_8sPjzINwGBlE6K6WQQy0KbF2m0VDZY5EAYa4mh4o84xiABCoYZYSEeA9FIzmYRJEVrqYHjQeVucZdqkDDCTEK49nVIR4hi8Mm1EItYDn__HDydZORotzfOHuLmB9xyVgBX_tcKJ9mND7MQJVeOumhDAx9QyXtRUhPhKUTDNgA~eyJhbGciOiJEUzEyOCJ9.eyJleHAiOjEzMzU1NTk0MTU3MzMsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTAwMDEifQ.BBoFaSGq0UAYDi9vdbsoBegeJ7FHVDxzODiV8MD8pF0emOPp1i_Uzg",
    root: {"algorithm":"RS","n":"13717766671510433111303151806101127171813773557424962001210686599690717644398501153133960329815327700526221729490916021955004415636643109524427762578738613915853895591332921269523141755077814022043323454871557827878869765578483437974192481801184235473918125161566266295979176194039841474030846700306142580608077665527626562098429368267997746767380874004089196208403356658867000112308693077043530239627194850786092251128137244380236693014852428390414510793421293487373711079360003639159681004539188014924495483277607084448583613608953997565952445532663265804891482606228128383798830560843667395414521699843061983900619","e":"65537"}
  }
];

var assertion = VECTORS[0].assertion;
var pk = jwcrypto.loadPublicKeyFromObject(VECTORS[0].root);
var now = new Date();

// times
var timeOfCert = 1335562698768;
var timeOfAssertion = 1335559415733;

// a bit before both cert and assertion
var timeThatShouldWork = new Date(Math.min(timeOfCert, timeOfAssertion) - 1000);

var suite = vows.describe('vectors');

suite.addBatch(
  {
    "verifying a test-vector assertion that is expired" : {
      topic: function() {
        jwcrypto.cert.verifyBundle(
          assertion, now, function(issuer, next) {
            next(null, pk);
          },
          this.callback);
      },
      "fails appropriately": function(err, certParamsArray, payload, assertionParams) {
        assert.equal(err, "assertion has expired");
      }
    }    
})

suite.addBatch(
  {
    "verifying a test-vector assertion with appropriate verif time" : {
      topic: function() {
        jwcrypto.cert.verifyBundle(
          assertion, timeThatShouldWork, function(issuer, next) {
            next(null, pk);
          },
          this.callback);
      },
      "succeed": function(err, certParamsArray, payload, assertionParams) {
        assert.isNull(err);
      },
      "contains the right fields": function(err, certParamsArray, payload, assertionParams) {
        assert.isNotNull(assertionParams.expiresAt);
        assert.isNotNull(assertionParams.expiresAt.getFullYear);        
        assert.isString(assertionParams.audience);

        assert.isUndefined(assertionParams.aud);
        assert.isUndefined(assertionParams.exp);        
        assert.isUndefined(payload.aud);
        assert.isUndefined(payload.exp);        
      }
    }    
});

suite.export(module);

