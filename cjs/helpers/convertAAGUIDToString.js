'use strict';

const { toHex } = require('./iso/isoUint8Array.js');

/**
 * 将 authData 中的 AAGUID 缓冲区转换为 UUID 字符串格式
 *
 * @param {Uint8Array} aaguid 原始 AAGUID 缓冲区
 * @returns {string} 格式化后的 UUID 字符串
 */
function convertAAGUIDToString(aaguid) {
    // 原始十六进制示例: adce000235bcc60a648b0b25f1f05503
    const hex = toHex(aaguid),
        segments = [
            hex.slice(0, 8),   // 前 8 位
            hex.slice(8, 12),  // 接下来 4 位
            hex.slice(12, 16), // 接下来 4 位
            hex.slice(16, 20), // 接下来 4 位
            hex.slice(20, 32), // 最后 12 位
        ];

    return segments.join('-'); // 格式化结果: adce0002-35bc-c60a-648b-0b25f1f05503
}

module.exports = { convertAAGUIDToString };