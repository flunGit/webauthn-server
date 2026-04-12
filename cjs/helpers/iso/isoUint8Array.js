'use strict';

/**
 * 用于处理 Uint8Array 的运行环境无关方法集合
 * @module
 */

/**
 * 确认两个 Uint8Array 是否深度相等
 *
 * @param {Uint8Array} array1
 * @param {Uint8Array} array2
 * @returns {boolean}
 */
function areEqual(array1, array2) {
    if (array1.length !== array2.length) return false;
    return array1.every((val, i) => val === array2[i]);
}

/**
 * 将 Uint8Array 转换为十六进制字符串
 *
 * 替代 `Buffer.toString('hex')`
 *
 * @param {Uint8Array} array
 * @returns {string} 十六进制字符串，例如 `adce000235bcc60a648b0b25f1f05503`
 */
function toHex(array) {
    const hexParts = Array.from(array, (i) => i.toString(16).padStart(2, '0'));
    return hexParts.join('');
}

/**
 * 将十六进制字符串转换为 Uint8Array
 *
 * 替代 `Buffer.from('...', 'hex')`
 *
 * @param {string} hex 十六进制字符串
 * @returns {Uint8Array}
 * @throws {Error} 如果提供的字符串不是有效的十六进制
 */
function fromHex(hex) {
    if (!hex) return new Uint8Array(0);

    const isValid = hex.length !== 0 && hex.length % 2 === 0 && !/[^a-fA-F0-9]/u.test(hex);
    if (!isValid) throw new Error('无效的十六进制字符串');

    const byteStrings = hex.match(/.{1,2}/g) ?? [];
    return Uint8Array.from(byteStrings.map((byte) => parseInt(byte, 16)));
}

/**
 * 将多个 Uint8Array 合并为一个 Uint8Array
 *
 * @param {Uint8Array[]} arrays 要合并的数组列表
 * @returns {Uint8Array}
 */
function concat(arrays) {
    let pointer = 0;
    const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0), toReturn = new Uint8Array(totalLength);

    arrays.forEach(arr => { toReturn.set(arr, pointer), pointer += arr.length });
    return toReturn;
}

/**
 * 将字节转换为 UTF-8 字符串
 *
 * @param {Uint8Array} array
 * @returns {string}
 */
function toUTF8String(array) {
    const decoder = new globalThis.TextDecoder('utf-8');
    return decoder.decode(array);
}

/**
 * 将 UTF-8 字符串转换回字节
 *
 * @param {string} utf8String
 * @returns {Uint8Array}
 */
function fromUTF8String(utf8String) {
    const encoder = new globalThis.TextEncoder();
    return encoder.encode(utf8String);
}

/**
 * 将 ASCII 字符串转换为 Uint8Array
 *
 * @param {string} value
 * @returns {Uint8Array}
 */
function fromASCIIString(value) {
    return Uint8Array.from(value.split('').map((x) => x.charCodeAt(0)));
}

/**
 * 准备一个 DataView,以便在解析 Uint8Array 中的字节时进行切片操作
 *
 * @param {Uint8Array} array
 * @returns {DataView}
 */
function toDataView(array) {
    return new DataView(array.buffer, array.byteOffset, array.length);
}

// 集中导出所有公共方法
module.exports = { areEqual, toHex, fromHex, concat, toUTF8String, fromUTF8String, fromASCIIString, toDataView };