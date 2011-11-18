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
    jwt = require("../jwt");

// signing
var ALG = "RS";
var KEYSIZE = 64;

// JWT
vows.describe('jwt').addBatch({
  "valid jwt" : {
    topic: function() {
      // generate a key
      var key = jwk.KeyPair.generate(ALG, KEYSIZE);
      var tok = new jwt.JWT("issuer.com", new Date(), "rp.com");
      return {
        key: key,
        token: tok.sign(key.secretKey)
      };
    },
    "token is approximately proper JWS format": function(topic) {
      assert.lengthOf(topic.token.split('.'), 3);
    },
    "token is properly signed": function(topic) {
      var json_ws = new jws.JWS();
      json_ws.parse(topic.token);
      assert.isTrue(json_ws.verify(topic.key.publicKey));
    },
    "token has proper assertion": function(topic) {
      var json_wt = new jwt.JWT();
      json_wt.parse(topic.token);
      json_wt.verify(topic.key.publicKey);
      assert.equal(json_wt.issuer, "issuer.com");
    }
  },
  "expired jwt" : {
    topic: function() {
      // generate a key
      var key = jwk.KeyPair.generate(ALG, KEYSIZE);
      var d = new Date();
      d.setTime(new Date().valueOf() - 300100);
      var tok = new jwt.JWT("issuer.com", d, "rp.com");
      return {
        key: key,
        token: tok.sign(key.secretKey)
      };
    },
    "does not verify": function(topic) {
      var json_wt = new jwt.JWT();
      json_wt.parse(topic.token);
      assert.isFalse(json_wt.verify(topic.key.publicKey));
    }
  }
}).export(module);