import type { Base64URLString, Uint8Array_ } from '../../types/index.js';
import * as tinyCbor from '@levischuck/tiny-cbor';
import { isoCrypto } from './isoCrypto/index.js';

// ================================= isoBase64URL.js =================================

/**
 * 点击左边加号查看接口定义的所有方法
 */
interface IsoBase64URLMethods {
    /**
     * - 将 Base64URL 编码的字符串解码为 ArrayBuffer，最适合用于将凭证 ID 从 JSON 字符串
     * - 转换为 ArrayBuffer 的场景，例如在 allowCredentials 或 excludeCredentials 中；
     *
     * @param base64urlString 要解码的 Base64URL 字符串值
     * @param from （可选）要使用的解码格式，当需要从标准 base64 解码时使用
     */
    toBuffer(base64urlString: string, from?: 'base64' | 'base64url'): Uint8Array;

    /**
     * - 将给定的 ArrayBuffer 编码为 Base64URL 字符串，非常适合将各种凭证响应中的
     * - ArrayBuffer 转换为字符串，以便作为 JSON 发送回服务器；
     *
     * @param buffer 要编码为 base64 的值
     * @param to （可选）要使用的编码格式，当需要编码为标准 base64 时使用
     */
    fromBuffer(buffer: Uint8Array, to?: 'base64' | 'base64url'): string;

    /**
     * - 将 base64url 字符串转换为标准 base64
     *
     * @param base64urlString 要转换的 Base64URL 字符串
     */
    toBase64(base64urlString: string): string;

    /**
     * - 将 UTF-8 字符串编码为 base64url
     *
     * @param utf8String 要编码的 UTF-8 字符串
     */
    fromUTF8String(utf8String: string): string;

    /**
     * - 将 base64url 字符串解码为其原始的 UTF-8 字符串
     *
     * @param base64urlString 要解码的 Base64URL 字符串
     */
    toUTF8String(base64urlString: string): string;

    /**
     * - 确认字符串是否为标准 base64 编码
     *
     * @param input 待检查的字符串
     */
    isBase64(input: string): boolean;

    /**
     * - 确认字符串是否为 base64url 编码，支持可选的填充字符
     *
     * @param input 待检查的字符串
     */
    isBase64URL(input: string): boolean;

    /**
     * - 移除 base64url 编码字符串中可选的填充字符
     *
     * @param input 包含可选填充字符的 Base64URL 字符串
     */
    trimPadding(input: Base64URLString): Base64URLString;
}

/**
 * 点击左边加号查看命名空间导出函数
 */
const isoBase64URL: IsoBase64URLMethods;

/**
 * ```js
 * // 文件导出内容(函数):
 * toBuffer();       // 将 Base64URL编码的字符串解码为 ArrayBuffer
 * fromBuffer();     // 将给定的 ArrayBuffer编码为 Base64URL
 * toBase64();       // 将 Base64URL字符串转换为标准 base64
 * fromUTF8String(); // 将 UTF-8字符串编码为 base64url
 * toUTF8String();   // 将 base64url字符串解码为其原始的 UTF-8
 * isBase64();       // 检查是否为 base64编码
 * isBase64URL();    // 检查是否为 base64url编码
 * trimPadding();    // 移除 base64url 编码字符串中可选的填充字符
 * ```
 * ---
 * - 查看定义:@see {@link toBuffer}、{@link fromBuffer}、{@link toBase64}、{@link fromUTF8String}
 * - {@link toUTF8String}、{@link isBase64}、{@link isBase64URL}、{@link trimPadding}
 */
module './isoBase64URL.js' {
    /**
     * 从接口中提取每个方法的类型,并声明对应的独立导出常量
     */
    const toBuffer: IsoBase64URLMethods['toBuffer'];
    const fromBuffer: IsoBase64URLMethods['fromBuffer'];
    const toBase64: IsoBase64URLMethods['toBase64'];
    const fromUTF8String: IsoBase64URLMethods['fromUTF8String'];
    const toUTF8String: IsoBase64URLMethods['toUTF8String'];
    const isBase64: IsoBase64URLMethods['isBase64'];
    const isBase64URL: IsoBase64URLMethods['isBase64URL'];
    const trimPadding: IsoBase64URLMethods['trimPadding'];

    export { toBuffer, fromBuffer, toBase64, fromUTF8String, toUTF8String, isBase64, isBase64URL, trimPadding };
}

// ================================= isoCBOR.js =================================

/**
 * CBOR 编解码工具方法接口
 *
 * - 无论使用何种 CBOR 编码器,在数据重新编码时都应保持 CBOR 数据的长度不变
 *
 * - 最关键的是,我们所使用的 CBOR 库必须满足以下条件：
 * - CBOR 映射类型值解码后必须得到 JavaScript 的 Map 对象
 * - 将 Uint8Array 编码回 CBOR 时，不得使用 CBOR 标签 64（uint8 类型数组）
 *
 * - 只要满足这些要求，CBOR 序列就可以自由地进行编码和解码,
 * - 同时保持其长度不变，从而能够最准确地在不同序列之间移动指针；
 * - 点击左边加号查看接口定义的所有方法
 */
interface IsoCBORMethods {
    /**
     * - 解码并返回 CBOR 编码值序列中的第一个项
     *
     * @param input 要解码的 CBOR 数据
     * @param asObject （可选）是否将任何 CBOR 映射转换为 JavaScript 对象，默认为 `false`
     */
    decodeFirst<Type>(input: Uint8Array_, asObject?: boolean): Type;

    /**
     * - 将数据编码为 CBOR
     *
     * @param input 要编码的 CBOR 兼容数据
     */
    encode(input: tinyCbor.CBORType): Uint8Array_;
}

/**
 * 点击左边加号查看命名空间导出函数
 */
const isoCBOR: IsoCBORMethods;

/**
 * ```js
 * // 文件导出内容(函数):
 * decodeFirst(); // 解码 CBOR 数据的第一个项
 * encode();      // 将数据编码为 CBOR
 * ```
 * ---
 * - 查看定义: @see {@link decodeFirst} ; {@link encode}
 */
module './isoCBOR.js' {
    /**
     * 从接口中提取每个方法的类型,并声明对应的独立导出常量
     */
    const decodeFirst: IsoCBORMethods['decodeFirst'];
    const encode: IsoCBORMethods['encode'];

    export { decodeFirst, encode };
}

// ================================= isoUint8Array.js =================================

/**
 * - Uint8Array 工具方法接口
 * - 点击左边加号查看接口定义的所有方法
 */
interface IsoUint8ArrayMethods {
    /**
     * 判断两个 Uint8Array 是否深层相等
     *
     * @param array1 第一个数组
     * @param array2 第二个数组
     */
    areEqual(array1: Uint8Array_, array2: Uint8Array_): boolean;

    /**
     * 将 Uint8Array 转换为十六进制字符串
     *
     * 替代 `Buffer.toString('hex')`
     *
     * @param array 要转换的 Uint8Array
     */
    toHex(array: Uint8Array_): string;

    /**
     * 将十六进制字符串转换为 Uint8Array
     *
     * 替代 `Buffer.from('...', 'hex')`
     *
     * @param hex 十六进制字符串
     */
    fromHex(hex: string): Uint8Array_;

    /**
     * 将多个 Uint8Array 合并成一个 Uint8Array
     *
     * @param arrays 要合并的 Uint8Array 数组
     */
    concat(arrays: Uint8Array_[]): Uint8Array_;

    /**
     * 将字节数组转换为 UTF-8 字符串
     *
     * @param array 包含 UTF-8 编码字节的 Uint8Array
     */
    toUTF8String(array: Uint8Array_): string;

    /**
     * 将 UTF-8 字符串转换回字节数组
     *
     * @param utf8String UTF-8 字符串
     */
    fromUTF8String(utf8String: string): Uint8Array_;

    /**
     * 将 ASCII 字符串转换为 Uint8Array
     *
     * @param value ASCII 字符串
     */
    fromASCIIString(value: string): Uint8Array_;

    /**
     * 准备一个 DataView，以便在解析 Uint8Array 中的字节时可以切片操作
     *
     * @param array 要转换的 Uint8Array
     */
    toDataView(array: Uint8Array_): DataView;
}

/**
 * 点击左边加号查看命名空间导出函数
 */
const isoUint8Array: IsoUint8ArrayMethods;

/**
 * ```js
 * // 文件导出内容(函数):
 * areEqual();        // 判断两个 Uint8Array 是否相等
 * toHex();           // 转换为十六进制字符串
 * fromHex();         // 从十六进制字符串创建 Uint8Array
 * concat();          // 合并多个 Uint8Array
 * toUTF8String();    // 将 Uint8Array 解码为 UTF-8 字符串
 * fromUTF8String();  // 将 UTF-8 字符串编码为 Uint8Array
 * fromASCIIString(); // 将 ASCII 字符串转换为 Uint8Array
 * toDataView();      // 转换为 DataView 对象
 * ```
 * ---
 * - 查看定义: @see {@link areEqual}、{@link toHex}、{@link fromHex}、{@link concat}
 * - {@link toUTF8String}、{@link fromUTF8String}、{@link fromASCIIString}、{@link toDataView}
 */
module './isoUint8Array.js' {
    /**
     * 从接口中提取每个方法的类型,并声明对应的独立导出常量
     */
    const areEqual: IsoUint8ArrayMethods['areEqual'];
    const toHex: IsoUint8ArrayMethods['toHex'];
    const fromHex: IsoUint8ArrayMethods['fromHex'];
    const concat: IsoUint8ArrayMethods['concat'];
    const toUTF8String: IsoUint8ArrayMethods['toUTF8String'];
    const fromUTF8String: IsoUint8ArrayMethods['fromUTF8String'];
    const fromASCIIString: IsoUint8ArrayMethods['fromASCIIString'];
    const toDataView: IsoUint8ArrayMethods['toDataView'];

    export { areEqual, toHex, fromHex, concat, toUTF8String, fromUTF8String, fromASCIIString, toDataView };
}

// ================================= 模块整体导出 =================================

/**
 *  iso工具库模块入口;
 *
 * - 本模块重新导出了所有子模块（isoBase64URL、isoCBOR、isoUint8Array）以及 isoCrypto 下的相关内容,
 * - 方便开发者从单一入口使用各类编码、解码、CBOR 处理和加密辅助函数;
 *
 * 本模块导出的主要函数包括：
 * ```js
 *  // isoBase64URL命名空间函数：
 *  toBuffer(), fromBuffer(), toBase64(), fromUTF8String(), toUTF8String(), isBase64(), isBase64URL(), trimPadding();
 *  // isoCBOR命名空间函数：
 * decodeFirst(), encode();
 *  // isoUint8Array命名空间函数：
 * areEqual(), toHex(), fromHex(), concat(), toUTF8String(), fromUTF8String(), fromASCIIString(), toDataView();
 *  // isoCrypto命名空间函数(来自 `./isoCrypto/index.js`):
 * digest(), getRandomValues(), verify();
 * ```
 * - 查看定义:@see {@link isoBase64URL}、{@link isoCBOR}、{@link isoUint8Array }、{@link isoCrypto}
 * - 具体函数请参考各子模块的文档。
 */
module './index.js' {
    // 重新导出所有子模块的内容
    export * from './isoBase64URL.js';
    export * from './isoCBOR.js';
    export * from './isoCrypto/index.js';
    export * from './isoUint8Array.js';
}