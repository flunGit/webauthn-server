/**
 * 一组与运行时无关的 CBOR 编解码方法
 * @module
 */
import * as tinyCbor from '@levischuck/tiny-cbor';

/**
 * 无论使用何种 CBOR 编码器，当数据重新编码时,都应保持 CBOR 数据的长度不变
 *
 * 最关键的是，我们使用的 CBOR 库必须满足以下要求：
 * - CBOR Map 类型值解码后必须是 JavaScript 的 Map 对象
 * - 将 Uint8Array 编码回 CBOR 时,不得使用 CBOR 标签 64（uint8 类型数组）
 *
 * 只要满足这些要求,CBOR 序列就可以自由地编解码，同时保持其长度,从而能够最精确地在各序列间移动指针;
 */

/**
 * 解码并返回一个 CBOR 编码值序列中的第一个项
 *
 * @param input 要解码的 CBOR 数据
 * @param asObject （可选）是否将任何 CBOR Map 转换为 JavaScript 对象,默认为 `false`
 */
function decodeFirst(input) {
    // 复制一份,避免修改原始数据
    const _input = new Uint8Array(input), decoded = tinyCbor.decodePartialCBOR(_input, 0), [first] = decoded;
    return first;
}

/**
 * 将数据编码为 CBOR
 */
function encode(input) {
    return tinyCbor.encodeCBOR(input);
}

export { decodeFirst, encode };