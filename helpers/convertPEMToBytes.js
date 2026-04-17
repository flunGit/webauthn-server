import { toBuffer } from './iso/isoBase64URL.js';

/**
 * 将 PEM 格式的证书转换为字节数组
 * - 查看定义:@see {@link convertPEMToBytes}
 */
const convertPEMToBytes = pem => {
    const certBase64 = pem
        .replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace(/[\n ]/g, '');
    return toBuffer(certBase64, 'base64');
};

export { convertPEMToBytes };