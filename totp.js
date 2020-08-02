const HMAC = require('https://raw.githubusercontent.com/coajaxial/espruino-hmac/master/hmac.js');
const base32 = require('https://raw.githubusercontent.com/coajaxial/espruino-base32/master/base32.js');

function generateOtp(hmac, digits) {
  "compiled";
  const o = hmac[hmac.byteLength - 1] & 0x0F;
  const dt = ((hmac[o] & 0x7f) << 24) | (hmac[o + 1] << 16) | (hmac[o + 2] << 8) | hmac[o + 3];
  let result = '' + dt % Math.pow(10, digits);
  while ( result.length < digits ) {
    result = '0' + result;
  }
  return result;
}

const TOTP = function(secret) {
  this.hmac = new HMAC.FixedSHA1(base32.decode(secret), 8);
  this.message = new Uint8Array(8);
};

TOTP.prototype.generate = function(timestamp, digits, tokenPeriod) {
  const epoch = Math.floor(timestamp / tokenPeriod);
  this.message.set([epoch >> 24 & 0xFF, epoch >> 16 & 0xFF, epoch >> 8 & 0xFF, epoch & 0xFF], 4);
  const hmac = this.hmac.digest(this.message.buffer);
  return generateOtp(hmac, digits);
};

exports.create = function(secret) {
  return new TOTP(secret);
};
