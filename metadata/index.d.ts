import {
    AlgSign, parseJWT, verifyAttestationWithMetadata, algSignToCOSEInfoMap, verifyJWT, verifyMDSBlob
} from './metadata.js';
/**
 *
 * 模块导出内容：
 * ```js
 * const AlgSign=[];                // 支持的签名算法数组
 * parseJWT();                      // 将 JWT 处理为 JavaScript 友好的数据结构
 * const algSignToCOSEInfoMap={};   // 将 ALG_SIGN 值转换为 COSE 信息
 * verifyAttestationWithMetadata(); // 将身份验证器的证明声明属性与 FIDO 联盟元数据服务中注册的预期值进行
 * verifyJWT();                     // 对对 FIDO MDS JWT 的轻量级验证(支持EC2和RSA算法);
 * verifyMDSBlob(); // 对 BLOB 进行真实性与完整性验证,并提取其中包含的 FIDO2,该方法会发起网络请求以执行 CRL 检查等操作;
 * ```
 * - 查看定义:{@link AlgSign}、{@link parseJWT}、 {@link algSignToCOSEInfoMap}、{@link verifyAttestationWithMetadata}、
 * {@link verifyJWT}、 {@link verifyMDSBlob}
 */
declare module './index.js' { }

export * from './metadata.js';