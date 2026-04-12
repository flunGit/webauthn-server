import { getWebCrypto } from './getWebCrypto.js';
async function importKey(opts) {
    const WebCrypto = await getWebCrypto(), { keyData, algorithm } = opts;
    return WebCrypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
}

export { importKey };