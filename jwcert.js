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

//
// certs based on JWS
//

// a sample JWCert:
//
// {
//   iss: "example.com",
//   exp: "1313971280961",
//   public-key: {
//     alg: "RS256",
//     value: "-----BEGIN PUBLIC KEY-----MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIn8oZeKoif0us1CTj12zGveebf1FfEmlBW2Gh38kejVP2fSgjSWtMuHzzCcQuWwxCe3M5L5My9BgOtcsyQCzpECAwEAAQ==-----END PUBLIC KEY-----"
//   },
//   principal: {
//     email: "john@example.com"
//   }
// }
//
//
// for intermediate certificates, fake subdomains of the issuer can be used,
// with a different type of principal
//
// {
//   iss: "example.com",
//   exp: "1313971280961",
//   public-key: {
//     alg: "RS",
//     value: "-----BEGIN PUBLIC KEY-----MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIn8oZeKoif0us1CTj12zGveebf1FfEmlBW2Gh38kejVP2fSgjSWtMuHzzCcQuWwxCe3M5L5My9BgOtcsyQCzpECAwEAAQ==-----END PUBLIC KEY-----"
//   },
//   principal: {
//     host: "intermediate1.example.com"
//   }
// }

var libs = require("./libs/all"),
    utils = require("./utils"),
    jws = require("./jws");

function JWCert(issuer, expires, pk, principal) {
  this.init(issuer, expires, pk, principal);
};

JWCert.prototype = new jws.JWS();

// add some methods

JWCert.prototype.init = function(issuer, expires, pk, principal) {
  this.issuer = issuer;
  this.expires = expires;
  this.pk = pk;
  this.principal = principal;
};

JWCert.prototype.serializePayload = function() {
  return JSON.stringify({
    iss: this.issuer,
    exp: this.expires.valueOf(),
    "public-key": {
      alg: this.pk.algorithm,
      value: this.pk.serialize()
    },
    principal: this.principal
  });
};

// this is called automatically by JWS
// after verification
JWCert.prototype.deserializePayload = function(payload) {
  var obj = JSON.parse(payload);
  var d = new Date();
  d.setTime(obj.exp);

  var pk = jws.getByAlg(obj['public-key'].alg).PublicKey.deserialize(obj['public-key'].value);
  
  this.init(obj.iss, d, pk, obj.principal);
};

exports.JWCert = JWCert;

