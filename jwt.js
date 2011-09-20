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

function JWT(issuer, expires, audience) {
  this.init(issuer, expires, audience);
}

JWT.prototype =  new jws.JWS();

// add some methods

JWT.prototype.init = function(issuer, expires, audience) {
  this.issuer = issuer;
  this.expires = expires;
  this.audience = audience;
};

JWT.prototype.serializePayload = function() {
  // make the issuer optional
  var assertion = {
    exp: this.expires.valueOf(),
    aud: this.audience
  };
  
  if (this.issuer)
    assertion.iss = this.issuer;

  return JSON.stringify(assertion);
};

// this is called automatically by JWS
// after verification
JWT.prototype.deserializePayload = function(payload) {
  var obj = JSON.parse(payload);
  var d = new Date();
  d.setTime(obj.exp);
  this.init(obj.iss, d, obj.aud);
};

// this is called automatically by JWS
// after verification and deserialization to ensure that
// the payload verifies
JWT.prototype.verifyPayload = function() {
  // 2 minute window
  var diff = Math.abs(this.expires.valueOf() - new Date().valueOf());

  return (diff <= 2000);
};

exports.JWT = JWT;
