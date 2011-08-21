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
 * The Original Code is trusted.js; substantial portions derived
 * from XAuth code originally produced by Meebo, Inc., and provided
 * under the Apache License, Version 2.0; see http://github.com/xauth/xauth
 *
 * Contributor(s):
 *     Ben Adida <benadida@mozilla.com>
 *     Michael Hanson <mhanson@mozilla.com>
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

var libs = require("./libs/all"),
    utils = require("./utils"),
    jws = require("./jws");

function Assertion(issuer, expires, audience) {
  this.issuer = issuer;
  this.expires = expires;
  this.audience = audience;
}

Assertion.prototype = {
  serialize : function() {
    return JSON.stringify({
      iss: this.issuer,
      exp: this.expires,
      aud: this.audience
    });
  }
};

Assertion.deserialize = function(str) {
  var obj = JSON.parse(str);
  return new Assertion(obj.iss, obj.exp, obj.aud);
};

function JWT(algorithm, assertion) {
  if (assertion) {
    this.assertion = assertion;
    this.setJWS(new jws.JWS(algorithm, assertion.serialize()));
  }
}

JWT.prototype = {
  getAssertion: function() {
    if (!this.assertion) {
      if (!this.payload)
        return null;

      this.assertion = Assertion.deserialize(this.payload);
    }
    
    return this.assertion;
  },

  setJWS: function(jws) {
    this.jws = jws;

    // after JWT's own functions, delegate to the JWS;
    this.__proto__.__proto__ = this.jws;
  }    
}

JWT.parse = function(str) {
  var new_jws = jws.JWS.parse(str);
  var jwt = new JWT();
  jwt.setJWS(new_jws);
  return jwt;  
}

exports.JWT = JWT;
exports.Assertion = Assertion;
