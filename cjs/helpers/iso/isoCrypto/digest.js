'use strict';

const { mapCoseAlgToWebCryptoAlg } = require('./mapCoseAlgToWebCryptoAlg.js'), { getWebCrypto } = require('./getWebCrypto.js');

/**
 * 生成所提供数据的摘要（哈希值）;
 *
 * @param data 要生成摘要的数据
 * @param algorithm COSE 算法 ID，该 ID 映射到所需的 SHA 算法
 */
async function digest(data, algorithm) {
    const WebCrypto = await getWebCrypto(), subtleAlgorithm = mapCoseAlgToWebCryptoAlg(algorithm),
        hashed = await WebCrypto.subtle.digest(subtleAlgorithm, data);
    return new Uint8Array(hashed);
}

module.exports = { digest };