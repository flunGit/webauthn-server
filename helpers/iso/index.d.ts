import { _getWebCryptoInternals, getWebCrypto, MissingWebCrypto } from './getWebCrypto.js';
import { importKey } from './importKey.js';
import {
    fromBuffer, utf8Tob64url, toBuffer, toBase64, b64urlToUtf8, isBase64, isBase64URL, trimPadding
} from './isoBase64URL.js';
import { decodeFirst, encode } from './isoCBOR.js';
import {
    fromHex, utf8Tobytes, asciiToBytes, toHex, toDataView, bytesToUtf8, areEqual, concat
} from './isoUint8Array.js';
import { digest, getRandomValues, verify } from './output.js';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg.js';
import { mapCoseAlgToWebCryptoKeyAlgName } from './mapCoseAlgToWebCryptoKeyAlgName.js';
import { unwrapEC2Signature } from './unwrapEC2Signature.js';
import { verifyEC2 } from './verifyEC2.js';
import { verifyOKP } from './verifyOKP.js';
import { verifyRSA } from './verifyRSA.js';

// ================================= getWebCrypto.js =================================
/**
 * ```js
 * // 文件导出内容:
 *
 * // 类
 * class MissingWebCrypto{};     // 当无法在当前运行时环境中定位到 Crypto API 实例时抛出的错误;
 *
 * // 常量
 * const _getWebCryptoInternals; // 内部使用的辅助对象,主要用于测试时模拟和重置缓存;
 *
 * // 函数
 * getWebCrypto();               // 尝试从当前运行时获取Crypto API的实例,支持Node(v20+)及现代浏览器环境;
 * ```
 * ---
 * - 查看定义:@see {@link getWebCrypto}、{@link MissingWebCrypto}、{@link _getWebCryptoInternals}
 */
declare module './getWebCrypto.js' {
    export * from './getWebCrypto.js';
}

// ================================= importKey.js =================================
/**
 * ```js
 * // 文件导出内容
 * importKey(); // 导入一个用于签名验证的 JSON Web Key (JWK) 格式密钥
 * ```
 * - 查看定义:@see {@link importKey}
 */
declare module './importKey.js' {
    export * from './importKey.js';
}

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
declare module './isoBase64URL.js' {
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
declare module './isoCBOR.js' {
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
declare module './isoUint8Array.js' {
    export * from './isoUint8Array.js';
}


// ================================= mapCoseAlgToWebCryptoAlg.js =================================
/**
 * 将 COSE 算法标识符转换为 WebCrypto API 所期望的对应字符串值
 * ```js
 * // 文件导出内容
 * mapCoseAlgToWebCryptoAlg(); //
 * ```
 * - 查看定义:@see {@link mapCoseAlgToWebCryptoAlg}
 */
declare module './mapCoseAlgToWebCryptoAlg.js' {
    export * from './mapCoseAlgToWebCryptoAlg.js';
}

// ================================= mapCoseAlgToWebCryptoKeyAlgName.js =================================
/**
 * ```js
 * // 文件导出内容
 * mapCoseAlgToWebCryptoKeyAlgName(); // 将 COSE 算法标识符(alg ID)转换为WebCrypto API所期望的对应密钥算法字符串值
 * ```
 * - 查看定义:@see {@link mapCoseAlgToWebCryptoKeyAlgName}
 */
declare module './mapCoseAlgToWebCryptoKeyAlgName.js' {
    export * from './mapCoseAlgToWebCryptoKeyAlgName.js';
}

// ================================= output.js =================================
/**
 * ```js
 * // 文件导出内容:
 * digest();          // 生成所提供数据的摘要;
 * getRandomValues(); // 使用与数组长度相等的随机字节填充传入的字节数组;
 * verify();          // 使用公钥验证签名,支持 EC2 和 RSA 公钥;
 * ```
 * - 查看定义:@see {@link digest}、{@link getRandomValues}、{@link verify}
 */
declare module './output.js' {
    export * from './output.js';
}

// ================================= structs.js =================================
/**
 * ```js
  * // 文件导出内容
 * type SubtleCryptoAlg; type SubtleCryptoCrv; type SubtleCryptoKeyAlgName;
 * ```
 * - 查看定义:@see {@link SubtleCryptoAlg}、{@link SubtleCryptoCrv}、{@link SubtleCryptoKeyAlgName}
 */
declare module './structs.js' {
    export type SubtleCryptoAlg = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
    export type SubtleCryptoCrv = 'P-256' | 'P-384' | 'P-521' | 'Ed25519';
    export type SubtleCryptoKeyAlgName = 'ECDSA' | 'Ed25519' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS';
}

// ================================= unwrapEC2Signature.js =================================
/**
 * ```js
 * // 文件导出内容
 * unwrapEC2Signature(); // 从EC2签名的 ASN.1 结构中提取出 r 和 s;
 * ```
 * - 查看定义:@see {@link unwrapEC2Signature}
 */
declare module './unwrapEC2Signature.js' {
    export * from './unwrapEC2Signature.js';
}

// ================================= verifyEC2.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyEC2(); // 使用 EC2 公钥验证签名
 * ```
 * - 查看定义:@see {@link verifyEC2}
 */
declare module './verifyEC2.js' {
    export * from './verifyEC2.js';
}

// ================================= verifyOKP.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyOKP(); // 验证 OKP 类型的 COSE 签名
 * ```
 * - 查看定义:@see {@link verifyOKP}
 */
declare module './verifyOKP.js' {
    export * from './verifyOKP.js';
}

// ================================= verifyRSA.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyRSA(); // 使用 RSA 公钥验证签名
 * ```
 * - 查看定义:@see {@link verifyRSA}
 */
declare module './verifyRSA.js' {
    export * from './verifyRSA.js';
}

// ================================= 模块整体导出 =================================

/**
 *  iso工具库模块入口;
 *
 * - 本模块主要对外导出的子模块为:`digest、getRandomValues、verify、verifyEC2、verifyOKP、verifyRSA、isoBase64URL、isoCBOR、isoUint8Array`;
 * - 方便开发者从单一入口使用各类编码、解码、CBOR 处理和加密辅助函数;
 *
 * 本模块导出的主要函数包括：
 * ```js
 * digest(), getRandomValues(), verify(); // output文件
 * verifyEC2();                           // verifyEC2文件
 * verifyOKP();                           // verifyOKP文件
 * verifyRSA();                           // verifyRSA文件
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
 * - 查看定义:@see {@link digest}、{@link getRandomValues}、{@link verify }、{@link verifyEC2 }、{@link verifyOKP}、{@link verifyRSA}
 * - isoBase64URL文件函数：{@link fromBuffer}、{@link utf8Tob64url}、{@link toBuffer}、{@link toBase64}、
 *  {@link b64urlToUtf8}、{@link isBase64}、{@link isBase64URL}、{@link trimPadding}
 * - isoUint8Array文件函数:{@link fromHex}、{@link utf8Tobytes}、{@link asciiToBytes}、{@link toHex}、{@link toDataView}、
 *  {@link bytesToUtf8}、{@link areEqual}、{@link concat}
 */
declare module './index.js' { }
export * from './getWebCrypto.js';
export * from './importKey.js';
export * from './isoBase64URL.js';
export * from './isoCBOR.js';
export * from './isoUint8Array.js';
export * from './mapCoseAlgToWebCryptoAlg.js';
export * from './mapCoseAlgToWebCryptoKeyAlgName.js';
export * from './output.js';
export * from './unwrapEC2Signature.js';
export * from './verifyEC2.js';
export * from './verifyOKP.js';
export * from './verifyRSA.js';