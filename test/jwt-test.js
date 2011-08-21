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
    jwt = require("../jwt");

// signing
var ALG = "RS";
var KEYSIZE = 64;

vows.describe('sign').addBatch(
  {
    "generate keypair" : {
      topic: function() {
        return jwt.getByAlg(ALG).KeyPair.generate(KEYSIZE);
      },
      "is a keypair": function(keypair) {
        assert.instanceOf(keypair, jwt.getByAlg(ALG).KeyPair);
      },
      "should have right algorithm": function(keypair) {
        assert.equal(keypair.algorithm, ALG);
      },
      "should have right number of bits": function(keypair) {
        assert.equal(keypair.keysize, KEYSIZE);
      },
      "should have secret key": function(keypair) {
        assert.notEqual(keypair.secretKey, null);
      },
      "with a message": {
        topic: function(keypair) {
          var message_to_sign= "testing!";
          return message_to_sign;
        },
        "to sign": {
          topic: function(message, keypair) {
            return keypair.secretKey.sign(message);
          },
          "signature looks okay": function(signature) {
            assert.notEqual(signature, null);
          },
          "signature": {
            topic: function(signature, message, keypair) {
              return keypair.publicKey.verify(message, signature);
            },
            "validates": function(result) {
              assert.isTrue(result);
            }
          }
        },
        "to sign with serialization": {
          topic: function(message, keypair) {
            var serialized_sk = keypair.secretKey.serialize();
            var reserialized_sk = jwt.getByAlg(ALG).SecretKey.deserialize(serialized_sk);
            return reserialized_sk.sign(message);
          },
          "signature looks okay": function(signature) {
            assert.notEqual(signature, null);
          },
          "signature": {
            topic: function(signature, message, keypair) {
              var serialized_pk = keypair.publicKey.serialize();
              var reserialized_pk = jwt.getByAlg(ALG).PublicKey.deserialize(serialized_pk);
              return reserialized_pk.verify(message, signature);
            },
            "validates": function(result) {
              assert.isTrue(result);
            }
          }
        }
      }
    }
  }).export(module);

// JWT
vows.describe('jwt').addBatch({
  "generate jwt" : {
    topic: function() {
      // generate a key
      var key = jwt.getByAlg(ALG).KeyPair.generate(KEYSIZE);
      var tok = new jwt.WebToken(key.getJWTAlgorithm(),{foo:"bar"});
      return {
        key: key,
        token: tok.sign(key.secretKey)
      };
    },
    "token is approximately proper JWT format": function(topic) {
      assert.length(topic.token.split('.'), 3);
    },
    "token is properly signed": function(topic) {
      var wt = jwt.WebToken.parse(topic.token);
      assert.isTrue(wt.verify(topic.key.publicKey));        
    }
  }
}).export(module);