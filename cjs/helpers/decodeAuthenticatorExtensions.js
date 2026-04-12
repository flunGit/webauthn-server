'use strict';

const { decodeFirst } = require('./iso/isoCBOR.js');

/**
 * 将认证器扩展数据缓冲区转换为合适的对象
 *
 * @param {Uint8Array} extensionData 认证器扩展数据缓冲区
 * @returns {Object} 解码并转换后的扩展数据对象
 */
function decodeAuthenticatorExtensions(extensionData) {
    let toCBOR;
    try {
        toCBOR = decodeFirst(extensionData);
    } catch (err) {
        throw new Error(`解码认证器扩展数据时出错: ${err.message}`);
    }
    return convertMapToObjectDeep(toCBOR);
}

/**
 * CBOR 编码的扩展数据可能是深层嵌套的 Map,简单使用 `Object.entries()` 无法处理;
 * 此方法会递归地将所有 Map 转换为普通对象;
 *
 * @param {Map} input 要转换的 Map 数据
 * @returns {Object} 转换后的普通对象
 */
function convertMapToObjectDeep(input) {
    const mapped = {};
    for (const [key, value] of input) {
        if (value instanceof Map) mapped[key] = convertMapToObjectDeep(value);
        else mapped[key] = value;
    }
    return mapped;
}

module.exports = { decodeAuthenticatorExtensions };