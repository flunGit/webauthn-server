import { isoCrypto } from './isoCrypto/index.js';
import {
    toBuffer, fromBuffer, toBase64, fromUTF8String, toUTF8String, isBase64, isBase64URL, trimPadding
} from './isoBase64URL.js';
import { decodeFirst, encode } from './isoCBOR.js';
import {
    areEqual, toHex, fromHex, concat, toUTF8String, fromUTF8String, fromASCIIString, toDataView
} from './isoUint8Array.js';

// ================================= isoBase64URL.js =================================
/**
 * ```js
 * // isoBase64URL命名空间导出函数
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
 * - 查看定义:@see {@link toBuffer}、{@link fromBuffer}、{@link toBase64}、{@link fromUTF8String}、
 *  {@link toUTF8String}、{@link isBase64}、{@link isBase64URL}、{@link trimPadding}
 */
const isoBase64URL = { toBuffer, fromBuffer, toBase64, fromUTF8String, toUTF8String, isBase64, isBase64URL, trimPadding };

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
    export * from './isoBase64URL.js';
}

// ================================= isoCBOR.js =================================
/**
 * ```js
 * // isoCBOR命名空间导出函数
 * decodeFirst(); // 解码 CBOR 数据的第一个项
 * encode();      // 将数据编码为 CBOR
 * ```
 * ---
 * - 查看定义:@see {@link decodeFirst}、{@link encode}
 */
const isoCBOR = { decodeFirst, encode };

/**
 * ```js
 * // 文件导出内容(函数):
 * decodeFirst(); // 解码 CBOR 数据的第一个项
 * encode();      // 将数据编码为 CBOR
 * ```
 * ---
 * - 查看定义:@see {@link decodeFirst} ; {@link encode}
 */
module './isoCBOR.js' {
    export * from './isoCBOR.js';
}

// ================================= isoUint8Array.js =================================
/**
 * ```js
 * // isoUint8Array命名空间导出函数
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
 * - 查看定义:@see {@link areEqual}、{@link toHex}、{@link fromHex}、{@link concat}、
 *  {@link toUTF8String}、{@link fromUTF8String}、{@link fromASCIIString}、{@link toDataView}
 */
const isoUint8Array = { areEqual, toHex, fromHex, concat, toUTF8String, fromUTF8String, fromASCIIString, toDataView };

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
 * - 查看定义:@see {@link areEqual}、{@link toHex}、{@link fromHex}、{@link concat}
 * - {@link toUTF8String}、{@link fromUTF8String}、{@link fromASCIIString}、{@link toDataView}
 */
module './isoUint8Array.js' {
    export * from './isoUint8Array.js';
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
 * - 查看定义:@see {@link isoCrypto}、{@link isoCBOR}、{@link isoUint8Array }、{@link isoBase64URL}
 * - 具体函数请参考各子模块的文档。
 */
module './index.js' { }
export { isoCrypto, isoBase64URL, isoCBOR, isoUint8Array }