import { toBuffer } from './iso/index.js';

/**
 * 将 PEM 格式的证书转换为字节数组
 * - 查看定义:@see {@link convertPEMToBytes}
 *
 * @param {string} pem - PEM 格式的证书字符串
 * @returns {Uint8Array} 解码后的 DER 证书字节数组
 */
const convertPEMToBytes = pem => {
    const certBase64 = pem
        .replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace(/[\n ]/g, '');
    return toBuffer(certBase64, 'base64');
};

export { convertPEMToBytes };