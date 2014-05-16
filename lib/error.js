/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

function JwcryptoError(message) {
  Error.call(this);
  this.message = message;
}

JwcryptoError.prototype = Object.create(Error.prototype);
JwcryptoError.prototype.constructor = JwcryptoError;
JwcryptoError.prototype.name = 'JwcryptoError';

function defineError(name) {
  function E(msg) {
    JwcryptoError.call(this, msg);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, E);
    }
  }
  E.prototype = Object.create(JwcryptoError.prototype);
  E.prototype.name = name;
  E.prototype.constructor = E;
  return E;
}

exports.MalformedError = defineError('MalformedInput');
exports.KeySizeNotSupportedError = defineError('KeySizeNotSupported');
exports.NotImplementedError = defineError('NotImplemented');
