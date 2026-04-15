import { getWebCrypto } from './getWebCrypto.js';
const importKey = async opts => {
    const WebCrypto = await getWebCrypto(), { keyData, algorithm } = opts;
    return WebCrypto.subtle.importKey('jwk', keyData, algorithm, false, ['verify']);
}

export { importKey };