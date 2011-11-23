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
    vep = require("../vep"),
    jwk = require("../jwk"),
    jwcert = require("../jwcert"),
    jwt = require("../jwt"),
    events = require("events");

var ALG="RS";
var KEYSIZE=64;

var root_kp = jwk.KeyPair.generate(ALG, KEYSIZE);

vows.describe('vep').addBatch({
  "generate params and bundle them" : {
    topic: function() {
      // generate user keys
      var user_kp = jwk.KeyPair.generate(ALG, KEYSIZE);

      // generate the cert on user key from root
      var raw_expiration = new Date().valueOf() + 60000
      var expiration = new Date();
      expiration.setTime(raw_expiration);

      var user_cert = new jwcert.JWCert("root.com", expiration, new Date(), user_kp.publicKey, {email: "john@root.com"}).sign(root_kp.secretKey);

      // generate assertion
      assertionExpiration = new Date(new Date().getTime() + (2 * 60 * 1000));
      var tok = new jwt.JWT(null, assertionExpiration, "rp.com");
      var assertion = tok.sign(user_kp.secretKey);

      // bundle
      var full_assertion = vep.bundleCertsAndAssertion([user_cert], assertion);
      var unbundled_stuff = vep.unbundleCertsAndAssertion(full_assertion);

      return unbundled_stuff;
    },
    "contains right stuff": function(stuff) {
      assert.ok(stuff.assertion);
      assert.ok(stuff.certificates);
    },
    "verification": {
      topic: function(stuff) {
        var self = this;
        
        jwcert.JWCert.verifyChain(
          stuff.certificates,
          new Date(),
          function(issuer, next) {
            if (issuer == "root.com")
              next(root_kp.publicKey);
            else
              next(null);
          }, function(pk) {
            var tok = new jwt.JWT();
            tok.parse(stuff.assertion);
            var result = tok.verify(pk);
            self.callback(result);
          }, function(error) {
            self.callback(null);
          });
      },
      "still works": function(err, res) {
        assert.isTrue(res);
      }
    }
  }
}).export(module);