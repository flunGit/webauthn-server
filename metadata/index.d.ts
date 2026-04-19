import { AlgSign } from './mdsTypes.js';
import { parseJWT } from './parseJWT.js';
import { algSignToCOSEInfoMap, verifyAttestationWithMetadata } from './verifyAttestationWithMetadata.js';
import { verifyJWT } from './verifyJWT.js';
import { verifyMDSBlob } from './verifyMDSBlob.js';

// ================================= mdsTypes.js =================================
/**
 * ```
 * // 文件导出内容
 * const AlgSign=[]; // 支持的签名算法数组
 * ```
 * - 查看定义:@see {@link AlgSign}
 */
module './mdsTypes.js' {
    export * from './mdsTypes.js';
}


// ================================= parseJWT.js =================================
/**
 * // 文件导出内容
 * parseJWT(); // 将 JWT 处理为 JavaScript 友好的数据结构
 * ```
 * - 查看定义:@see {@link parseJWT}
 */
module './parseJWT.js' {
    export * from './parseJWT.js';
}

// ================================= verifyAttestationWithMetadata.js =================================
/**
 * // 文件导出内容
 * const algSignToCOSEInfoMap={};   // 将 ALG_SIGN 值转换为 COSE 信息
 * verifyAttestationWithMetadata(); // 将身份验证器的证明声明属性与 FIDO 联盟元数据服务中注册的预期值进行匹配
 * ```
 * - 查看定义:@see {@link algSignToCOSEInfoMap}、{@link verifyAttestationWithMetadata}
 */
module './verifyAttestationWithMetadata.js' {
    export * from './verifyAttestationWithMetadata.js';
}

// ================================= verifyJWT.js =================================
/**
 * 针对 FIDO MDS JWT 的轻量级验证,支持 EC2 和 RSA 算法;
 * // 文件导出内容
 * verifyJWT(); //
 * ```
 * - 查看定义:@see {@link verifyJWT}
 */
module './verifyJWT.js' {
    export * from './verifyJWT.js';
}

// ================================= verifyMDSBlob.js =================================
/**
 * ```js
 * // 文件导出内容:
 * verifyMDSBlob(); // 对符合规范的 BLOB 进行真实性与完整性验证,并提取其中包含的 FIDO2,该方法会发起网络请求以执行 CRL 检查等操作;
 * ```
 * ---
 * - 查看定义:@see {@link verifyMDSBlob}
 */
module './verifyMDSBlob.js' {
    export * from './verifyMDSBlob.js';
}

// ================================= 模块整体导出 =================================
/**
 *
 * 模块导出内容：
 * ```js
 * const AlgSign=[]; // 支持的签名算法数组
 * ```
 * - 查看定义:@see {@link AlgSign}
 */
module './index.js' { }
export * from './mdsTypes.js';