import type { Base64URLString, Uint8Array_ } from '../../types/index.js';
import * as tinyCbor from '@levischuck/tiny-cbor';

/**
 *
 * @module
 */
declare module './index.js' {

}
// ================================= isoBase64URL.js =================================
declare namespace IsoBase64URL {
    /**
     * 将 Base64URL 编码的字符串解码为 ArrayBuffer,最适合用于将凭证 ID 从 JSON 字符串转换为 ArrayBuffer 的场景,
     * 例如在 allowCredentials 或 excludeCredentials 中;
     *
     * @param buffer 要解码的 Base64URL 字符串值
     * @param to (可选) 要使用的解码格式,当需要从标准 base64 解码时使用
     */
    function toBuffer(base64urlString: string, from?: 'base64' | 'base64url'): Uint8Array_;

    /**
     * 将给定的 ArrayBuffer 编码为 Base64URL 字符串,非常适合将各种凭证响应中的 ArrayBuffer 转换为字符串,
     * 以便作为 JSON 发送回服务器;
     *
     * @param buffer 要编码为 base64 的值
     * @param to (可选) 要使用的编码格式,当需要编码为标准 base64 时使用
     */
    function fromBuffer(buffer: Uint8Array_, to?: 'base64' | 'base64url'): string;

    /**
     * 将 base64url 字符串转换为标准 base64
     */
    function toBase64(base64urlString: string): string;

    /**
     * 将 UTF-8 字符串编码为 base64url
     */
    function fromUTF8String(utf8String: string): string;

    /**
     * 将 base64url 字符串解码为其原始的 UTF-8 字符串
     */
    function toUTF8String(base64urlString: string): string;

    /**
     * 确认字符串是否为标准 base64 编码
     */
    function isBase64(input: string): boolean;

    /**
     * 确认字符串是否为 base64url 编码,支持可选的填充字符
     */
    function isBase64URL(input: string): boolean;

    /**
     * 移除 base64url 编码字符串中可选的填充字符
     */
    function trimPadding(input: Base64URLString): Base64URLString;
}

// ================================= isoCBOR.js =================================
declare namespace IsoCBOR {
    /**
     * 无论使用何种 CBOR 编码器,在数据重新编码时都应保持 CBOR 数据的长度不变
     *
     * 最关键的是,我们所使用的 CBOR 库必须满足以下条件：
     * - CBOR 映射类型值解码后必须得到 JavaScript 的 Map 对象
     * - 将 Uint8Array 编码回 CBOR 时,不得使用 CBOR 标签 64（uint8 类型数组）
     *
     * 只要满足这些要求,CBOR 序列就可以自由地进行编码和解码,
     * 同时保持其长度不变,从而能够最准确地在不同序列之间移动指针;
     */

    /**
     * 解码并返回 CBOR 编码值序列中的第一个项
     *
     * @param input 要解码的 CBOR 数据
     * @param asObject （可选）是否将任何 CBOR 映射转换为 JavaScript 对象,默认为 `false`
     */
    function decodeFirst<Type>(input: Uint8Array_): Type;

    /**
     * 将数据编码为 CBOR
     */
    function encode(input: tinyCbor.CBORType): Uint8Array_;
}

// ================================= isoUint8Array.js =================================
declare namespace IsoUint8Array {
    /**
     * 判断两个 Uint8Array 是否深层相等
     */
    function areEqual(array1: Uint8Array_, array2: Uint8Array_): boolean;

    /**
     * 将 Uint8Array 转换为十六进制字符串;
     *
     * 替代 `Buffer.toString('hex')`
     */
    function toHex(array: Uint8Array_): string;

    /**
     * 将十六进制字符串转换为 Uint8Array;
     *
     * 替代 `Buffer.from('...', 'hex')`
     */
    function fromHex(hex: string): Uint8Array_;

    /**
     * 将多个 Uint8Array 合并成一个 Uint8Array
     */
    function concat(arrays: Uint8Array_[]): Uint8Array_;

    /**
     * 将字节数组转换为 UTF-8 字符串
     */
    function toUTF8String(array: Uint8Array_): string;

    /**
     * 将 UTF-8 字符串转换回字节数组
     */
    function fromUTF8String(utf8String: string): Uint8Array_;

    /**
     * 将 ASCII 字符串转换为 Uint8Array
     */
    function fromASCIIString(value: string): Uint8Array_;

    /**
     * 准备一个 DataView,以便在解析 Uint8Array 中的字节时可以切片操作
     */
    function toDataView(array: Uint8Array_): DataView;
}

// ================================= 模块整体导出 =================================
// 具名导出（支持 ESM 按需导入）
export const isoCrypto: typeof import('./isoCrypto/index.js');
export const isoBase64URL: typeof IsoBase64URL;
export const isoCBOR: typeof IsoCBOR;
export const isoUint8Array: typeof IsoUint8Array;

// export default _default;
// ================================= 子模块单独导入类型声明 =================================
// 以下声明使得直接 require 子路径文件（如 '../../../helpers/iso/isoUint8Array.js'）
// 也能获得正确的 TypeScript 类型提示;

declare module './isoBase64URL.js' {
    const base64: typeof IsoBase64URL;
    export default base64;
}

declare module './isoCBOR.js' {
    const cbor: typeof IsoCBOR;
    export default cbor;
}

declare module './isoUint8Array.js' {
    const uint8: typeof IsoUint8Array;
    export default uint8;
}