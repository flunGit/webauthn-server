'use strict';

const { toBuffer } = require('./iso/isoBase64URL.js');
/**
 * 将 PEM 格式的证书转换为字节数组
 *
 * @param {string} pem PEM 格式的证书字符串
 * @returns {Uint8Array} 证书的二进制字节数组
 */
function convertPEMToBytes(pem) {
    const certBase64 = pem.replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '').replace(/[\n ]/g, '');
    return toBuffer(certBase64, 'base64');
}

module.exports = { convertPEMToBytes };