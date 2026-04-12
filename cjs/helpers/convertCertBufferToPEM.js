'use strict';
const { isBase64URL, toBase64, isBase64, fromBuffer } = require('./iso/isoBase64URL.js');

/**
 * 将证书缓冲区转换为 OpenSSL 兼容的 PEM 文本格式
 *
 * @param {string | Uint8Array} certBuffer 证书缓冲区,可以是 base64 字符串、base64url 字符串或 Uint8Array
 * @returns {string} PEM 格式的证书字符串
 */
function convertCertBufferToPEM(certBuffer) {
    let b64cert;
    // 将 certBuffer 转换为 base64 表示
    if (typeof certBuffer === 'string') {
        if (isBase64URL(certBuffer)) b64cert = toBase64(certBuffer);
        else if (isBase64(certBuffer)) b64cert = certBuffer;
        else throw new Error('证书不是有效的 base64 或 base64url 字符串');

    }
    else b64cert = fromBuffer(certBuffer, 'base64');

    // 按每行 64 字符分割 base64 字符串
    let PEMKey = '';
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i += 1) {
        const start = 64 * i;
        PEMKey += `${b64cert.slice(start, 64)}\n`;
    }

    PEMKey = `-----BEGIN CERTIFICATE-----\n${PEMKey}-----END CERTIFICATE-----\n`;
    return PEMKey;
}

module.exports = { convertCertBufferToPEM };