import { digest, getRandomValues, verify, verifyEC2, verifyOKP, verifyRSA } from './isoCrypto/index.js';
import {
    fromBuffer, utf8Tob64url, toBuffer, toBase64, b64urlToUtf8, isBase64, isBase64URL, trimPadding
} from './isoBase64URL.js';
import { decodeFirst, encode } from './isoCBOR.js';
import {
    fromHex, utf8Tobytes, asciiToBytes, toHex, toDataView, bytesToUtf8, areEqual, concat
} from './isoUint8Array.js';

// ================================= isoBase64URL.js =================================
/**
 * ```js
 * // 文件导出内容(函数):
 * fromBuffer();   // 将给定的 ArrayBuffer编码为 Base64URL
 * utf8Tob64url(); // 将 UTF-8字符串编码为 base64url
 * toBuffer();     // 将 Base64URL编码的字符串解码为 ArrayBuffer
 * toBase64();     // 将 Base64URL字符串转换为标准 base64
 * b64urlToUtf8(); // 将 base64url字符串解码为其原始的 UTF-8
 * isBase64();     // 检查是否为 base64编码
 * isBase64URL();  // 检查是否为 base64url编码
 * trimPadding();  // 移除 base64url 编码字符串中可选的填充字符
 * ```
 * ---
 * - 查看定义:@see {@link fromBuffer}、{@link utf8Tob64url}、{@link toBuffer}、{@link toBase64}、
 *  {@link b64urlToUtf8}、{@link isBase64}、{@link isBase64URL}、{@link trimPadding}
 */
module './isoBase64URL.js' {
    export * from './isoBase64URL.js';
}

// ================================= isoCBOR.js =================================
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
 * // 文件导出内容(函数):
 * fromHex();      // 从十六进制字符串创建 Uint8Array
 * utf8Tobytes();  // 将 UTF-8 字符串编码为 Uint8Array
 * asciiToBytes(); // 将 ASCII 字符串转换为 Uint8Array
 * toHex();        // 转换为十六进制字符串
 * toDataView();   // 转换为 DataView 对象
 * bytesToUtf8();  // 将 Uint8Array 解码为 UTF-8 字符串
 * areEqual();     // 判断两个 Uint8Array 是否相等
 * concat();       // 合并多个 Uint8Array
 * ```
 * ---
 * - 查看定义:@see {@link fromHex}、{@link utf8Tobytes}、{@link asciiToBytes}、{@link toHex}、{@link toDataView}、
 *  {@link bytesToUtf8}、{@link areEqual}、{@link concat}
 */
module './isoUint8Array.js' {
    export * from './isoUint8Array.js';
}

// ================================= 模块整体导出 =================================

/**
 *  iso工具库模块入口;
 *
 * - 本模块重新导出了所有子模块`isoCrypto、isoBase64URL、isoCBOR、isoUint8Array`下的相关内容,
 * - 方便开发者从单一入口使用各类编码、解码、CBOR 处理和加密辅助函数;
 *
 * 本模块导出的主要函数包括：
 * ```js
 *  // isoCrypto目录导出函数：
 * digest(), getRandomValues(), verify(),verifyEC2(), verifyOKP(), verifyRSA;
 *
 *  // isoBase64URL.js文件函数：
 *   fromBuffer(),utf8Tob64url(), toBuffer(), toBase64(), b64urlToUtf8(), isBase64(), isBase64URL(), trimPadding();
 *
 *  // isoCBOR.js文件函数：
 * decodeFirst(), encode();
 *
 *  // isoUint8Array.js文件函数：
 * fromHex(), utf8Tobytes(), asciiToBytes(), toHex(), bytesToUtf8(), toDataView(),areEqual(), concat();
 * ```
 * - 查看定义:@see
 * - isoCrypto目录函数: {@link digest}、{@link getRandomValues}、{@link verify }、{@link verifyEC2 }、{@link verifyOKP}、{@link verifyRSA}
 * - isoBase64URL文件函数：{@link fromBuffer}、{@link utf8Tob64url}、{@link toBuffer}、{@link toBase64}、
 *  {@link b64urlToUtf8}、{@link isBase64}、{@link isBase64URL}、{@link trimPadding}
 * - isoUint8Array文件函数:{@link fromHex}、{@link utf8Tobytes}、{@link asciiToBytes}、{@link toHex}、{@link toDataView}、
 *  {@link bytesToUtf8}、{@link areEqual}、{@link concat}
 */
module './index.js' { }
export * from './isoCrypto/index.js';
export * from './isoBase64URL.js';
export * from './isoCBOR.js';
export * from './isoUint8Array.js';