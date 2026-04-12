'use strict';

/**
 * 用于处理 CBOR 编码的运行环境无关方法集合
 * @module
 */
const tinyCbor = require('@levischuck/tiny-cbor');

/**
 * 所使用的 CBOR 编码器需保证数据重新编码后长度不变
 *
 * 最重要的是，我们使用的 CBOR 库必须满足以下要求：
 * - CBOR Map 类型值必须解码为 JavaScript Map
 * - 将 Uint8Array 重新编码为 CBOR 时，不得使用 CBOR 标签 64（uint8 Typed Array）
 *
 * 只要满足这些要求,就可以在编码和解码 CBOR 序列时自由操作,
 * 同时保持其长度不变,以便最准确地移动内部指针;
 */

/**
 * 解码并返回 CBOR 编码值序列中的第一项
 *
 * @param {Uint8Array} input 要解码的 CBOR 数据
 * @param {boolean} [asObject=false] 是否将 CBOR Map 转换为 JavaScript 对象，默认为 false
 * @returns {any} 解码后的第一个值
 */
function decodeFirst(input) {
    // 创建副本以避免修改原始数据
    const _input = new Uint8Array(input), decoded = tinyCbor.decodePartialCBOR(_input, 0), [first] = decoded;
    return first;
}

/**
 * 将数据编码为 CBOR
 *
 * @param {any} input 要编码的数据
 * @returns {Uint8Array} CBOR 编码后的数据
 */
function encode(input) {
    return tinyCbor.encodeCBOR(input);
}

// 导出公共 API
module.exports = { decodeFirst, encode };