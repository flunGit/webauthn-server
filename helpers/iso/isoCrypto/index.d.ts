import { digest } from './digest.js';
import { getRandomValues } from './getRandomValues.js';
import { _getWebCryptoInternals, getWebCrypto, MissingWebCrypto } from './getWebCrypto.js';
import { importKey } from './importKey.js';
import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg.js';
import { mapCoseAlgToWebCryptoKeyAlgName } from './mapCoseAlgToWebCryptoKeyAlgName.js';
import { unwrapEC2Signature } from './unwrapEC2Signature.js';
import { verify } from './verify.js';
import { verifyEC2 } from './verifyEC2.js';
import { verifyOKP } from './verifyOKP.js';
import { verifyRSA } from './verifyRSA.js';

// ================================= digest.js =================================
/**
 * ```js
 * // 文件导出类容:
 * digest(); // 生成所提供数据的摘要;
 * ```
 * - 查看定义:@see {@link digest}
 */
module './isoBase64URL.js' {
    export * from './isoBase64URL.js';
}

// ================================= getRandomValues.js =================================
/**
 * ```js
 * // 文件导出类容
 * getRandomValues(); // 使用与数组长度相等的随机字节填充传入的字节数组;
 * ```
 * - 查看定义:@see {@link getRandomValues}
 */
module './getRandomValues.js' {
    export * from './getRandomValues.js';
}

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
module './importKey.js' {
    export * from './importKey.js';
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
module './mapCoseAlgToWebCryptoAlg.js' {
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
module './mapCoseAlgToWebCryptoKeyAlgName.js' {
    export * from './mapCoseAlgToWebCryptoKeyAlgName.js';
}

// ================================= structs.js =================================
/**
 * ```js
  * // 文件导出内容
 * type SubtleCryptoAlg; type SubtleCryptoCrv; type SubtleCryptoKeyAlgName;
 * ```
 * - 查看定义:@see {@link SubtleCryptoAlg}、{@link SubtleCryptoCrv}、{@link SubtleCryptoKeyAlgName}
 */
module './structs.js' {
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
module './unwrapEC2Signature.js' {
    export * from './unwrapEC2Signature.js';
}

// ================================= verify.js =================================
/**
 * ```js
 * // 文件导出内容
 * verify(); // 使用公钥验证签名,支持 EC2 和 RSA 公钥;
 * ```
 * - 查看定义:@see {@link verify}
 */
module './verify.js' {
    export * from './verify.js';
}

// ================================= verifyEC2.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyEC2(); // 使用 EC2 公钥验证签名
 * ```
 * - 查看定义:@see {@link verifyEC2}
 */
module './verifyEC2.js' {
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
module './verifyOKP.js' {
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
module './verifyRSA.js' {
    export * from './verifyRSA.js';
}

// ================================= 模块整体导出 =================================

/**
 *  isoCrypto工具库模块入口;
 *
 * ```js
 *  // 对外导出的函数：
 * digest(), getRandomValues(), verify();
 * ```
 * - 查看定义:@see {@link digest}、{@link getRandomValues}、{@link verify }
 */
module './index.js' { }
export * from './digest.js';
export * from './getRandomValues.js';
export * from './verify.js';
