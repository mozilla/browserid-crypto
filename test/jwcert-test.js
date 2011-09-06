/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Mozilla BrowserID.
 *
 * The Initial Developer of the Original Code is Mozilla.
 * Portions created by the Initial Developer are Copyright (C) 2011
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *     Ben Adida <benadida@mozilla.com>
 *     Mike Hanson <mhanson@mozilla.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

var vows = require("vows"),
    assert = require("assert"),
    jwk = require("../jwk"),
    jws = require("../jws"),
    jwcert = require("../jwcert"),
    events = require("events");

// signing
var ALG = "RS";
var KEYSIZE = 64;

// JWcert
vows.describe('jwcert').addBatch({
  "generate jwcert" : {
    topic: function() {
      // generate a key
      var key = jwk.KeyPair.generate(ALG, KEYSIZE);
      var tok = new jwcert.JWCert("issuer.com", new Date(), key.publicKey, {email:"john@issuer.com"});
      return {
        key: key,
        cert: tok.sign(key.secretKey)
      };
    },
    "cert is approximately proper JWS format": function(topic) {
      assert.length(topic.cert.split('.'), 3);
    },
    "cert is properly signed": function(topic) {
      var json_cert = new jws.JWS();
      json_cert.parse(topic.cert);
      assert.isTrue(json_cert.verify(topic.key.publicKey));
    },
    "cert is awesome": function(topic) {
      var json_cert = new jwcert.JWCert();
      json_cert.parse(topic.cert);
      assert.isTrue(json_cert.verify(topic.key.publicKey));
      assert.equal(json_cert.issuer, "issuer.com");
      assert.equal(json_cert.principal.email, "john@issuer.com");
    }
  },
  "generate cert chain" : {
    topic: function() {
      // generate three keypairs to chain things
      var root_kp = jwk.KeyPair.generate(ALG, KEYSIZE);
      var intermediate_kp = jwk.KeyPair.generate(ALG, KEYSIZE);
      var user_kp = jwk.KeyPair.generate(ALG, KEYSIZE);

      // generate the two certs
      var intermediate_cert = new jwcert.JWCert("root.com", new Date(), intermediate_kp.publicKey, {host: "intermediate.root.com"}).sign(root_kp.secretKey);
      var user_cert = new jwcert.JWCert("intermediate.root.com", new Date(), user_kp.publicKey, {email: "john@root.com"}).sign(intermediate_kp.secretKey);

      return {
        root_pk: root_kp.publicKey,
        certificates : [intermediate_cert, user_cert],
        user_pk : user_kp.publicKey
      };
    },
    "proper root": {
      topic: function(stuff) {
        var cb = this.callback;
        jwcert.JWCert.verifyChain(stuff.certificates, function(issuer, next) {
          if (issuer == "root.com")
            next(stuff.root_pk);
          else
            next(null);
        }, function(pk) {cb({pk:pk, stuff:stuff});});
      },
      "verifies": function(res, err) {
        assert.isTrue(res.pk.equals(res.stuff.user_pk));
      }
    },
    "improper root": {
      topic: function(stuff) {
        // this one should fail
        jwcert.JWCert.verifyChain(stuff.certificates, function(issuer, next) {
          if (issuer == "root.com")
            next(stuff.user_pk);
          else
            next(null);
        }, function(pk) {},this.callback);
      },
      "does not verify": function(message, err) {
        assert.isTrue(message != null);
      }
    }
  }
}).export(module);