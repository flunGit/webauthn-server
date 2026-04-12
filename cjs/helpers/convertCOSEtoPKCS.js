'use strict';

const { decodeFirst } = require('./iso/isoCBOR.js'), { concat } = require('./iso/isoUint8Array.js'),
    { COSEKEYS } = require('./cose.js');
/**
 * 将 COSE 编码的公钥转换为 PKCS 格式的密钥
 *
 * @param {Uint8Array} cosePublicKey COSE 编码的公钥数据
 * @returns {Uint8Array} PKCS 格式的密钥字节
 */
function convertCOSEtoPKCS(cosePublicKey) {
    // 这里处理得稍微宽松了一些,使用了 COSEPublicKeyEC2 结构,因为它可能同时包含 x 和 y,
    // 但如果没有 y,可能更合适的类型是 COSEPublicKeyOKP;
    // 暂时先这样处理,如果将来真的出现问题再回头优化;
    const struct = decodeFirst(cosePublicKey), tag = Uint8Array.from([0x04]), x = struct.get(COSEKEYS.x), y = struct.get(COSEKEYS.y);

    if (!x) throw new Error('COSE 公钥缺少 x 坐标');
    if (y) return concat([tag, x, y]);

    return concat([tag, x]);
}

module.exports = { convertCOSEtoPKCS };