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
    jwk = require("../jwk");
    jws = require("../jws");

// signing
var ALG = "RS";
var KEYSIZE = 64;

// JWS
vows.describe('jws').addBatch({
  "generate keypair" : {
    topic: function() {
      var key = jwk.KeyPair.generate(ALG, KEYSIZE);

      // serialize it and parse it twice
      var pk_str = key.publicKey.serialize();
      var pk1 = jwk.PublicKey.deserialize(pk_str);
      var pk2 = jwk.PublicKey.deserialize(pk_str);
      return {
        pk1: pk1,
        pk2: pk2
      };
    },
    "keys are equal" : function(topic) {
      assert.isTrue(topic.pk1.equals(topic.pk2));
    }
  },

  "generate jws" : {
    topic: function() {
      // generate a key
      var key = jwk.KeyPair.generate(ALG, KEYSIZE);
      var tok = new jws.JWS("stringtosign");
      return {
        key: key,
        token: tok.sign(key.secretKey)
      };
    },
    "token is approximately proper JWS format": function(topic) {
      assert.lengthOf(topic.token.split('.'), 3);
    },
    "token is properly signed": function(topic) {
      var wt = new jws.JWS();
      wt.parse(topic.token);
      assert.isTrue(wt.verify(topic.key.publicKey));
      assert.equal(wt.payload, "stringtosign");
    }
  },
  
  "generate jws async" : {
    topic: function() {
      // generate a key
      var key = jwk.KeyPair.generate(ALG, KEYSIZE);
      var tok = new jws.JWS("stringtosign");
      var self = this;
      tok.sign(key.secretKey, function() {}, function(token) {
        self.callback({
          key: key,
          token: token
        });
      });
    },
    "token is approximately proper JWS format": function(topic, err) {
      assert.lengthOf(topic.token.split('.'), 3);
    },
    "token is properly signed": function(topic, err) {
      var wt = new jws.JWS();
      wt.parse(topic.token);
      assert.isTrue(wt.verify(topic.key.publicKey));
      assert.equal(wt.payload, "stringtosign");
    }
  }
}).export(module);