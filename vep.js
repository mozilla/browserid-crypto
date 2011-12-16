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

// VEP parameters
var utils = require("./utils");

params = {
  algorithm: "RS",
  keysize: 256
};

// takes an array of serialized certs and a serialized assertion
function bundleCertsAndAssertion(certificates, assertion, new_format) {
  if (new_format) {
    if (!Array.isArray(certificates) || !certificates.length) {
      throw "certificates must be a non-empty array"
    }
    return [].concat(assertion, certificates).join('~');
  } else {
    var str = JSON.stringify({
      certificates: certificates,
      assertion: assertion
    });

    return utils.base64urlencode(str);
  }
}

// returns an object with certificates and assertion
function unbundleCertsAndAssertion(bundle) {
  // if there are tilde's, this is a "new format" bundle
  if (bundle.indexOf('~') !== -1) {
    var arr = bundle.split(['~']);
    var assertion = arr.shift();
    var certificates = arr;
    return {
      assertion: assertion,
      certificates: certificates
    };
  } else {
    return JSON.parse(utils.base64urldecode(bundle));
  }
}

exports.params = params;
exports.bundleCertsAndAssertion = bundleCertsAndAssertion;
exports.unbundleCertsAndAssertion = unbundleCertsAndAssertion;
