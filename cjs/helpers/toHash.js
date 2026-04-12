'use strict';

const { isoUint8Array, isoCrypto } = require('./iso/index.js');
/**
 * 返回给定数据的哈希摘要,可指定哈希算法,默认使用 SHA-256。
 *
 * @param {string | Uint8Array} data 要计算哈希的数据
 * @param {number} [algorithm=-7] 算法标识符（例如 -7 表示 SHA-256）
 * @returns {Uint8Array} 哈希摘要
 */
function toHash(data, algorithm = -7) {
    if (typeof data === 'string') data = isoUint8Array.fromUTF8String(data);

    const digest = isoCrypto.digest(data, algorithm);
    return digest;
}

module.exports = { toHash };