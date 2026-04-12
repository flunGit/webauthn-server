'use strict';

const { getWebCrypto } = require('./getWebCrypto.js');
async function importKey(opts) {
    const WebCrypto = await getWebCrypto(), { keyData, algorithm } = opts;
    return WebCrypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
}

module.exports = { importKey };