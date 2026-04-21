import {
    AlgSign, parseJWT, verifyAttestationWithMetadata, algSignToCOSEInfoMap, verifyJWT, verifyMDSBlob, BaseMetadataService,
    MetadataService
} from './metadata.js';
import { BaseSettingsService, SettingsService } from './settings.js';

// ================================= metadata.js =================================
/**
 *
 * 文件导出内容：
 * ```js
 * const AlgSign=[];                               // 支持的签名算法数组
 * parseJWT();                                     // 将 JWT 处理为 JavaScript 友好的数据结构
 * const algSignToCOSEInfoMap={};                  // 将 ALG_SIGN 值转换为 COSE 信息
 * verifyAttestationWithMetadata();                // 将身份验证器的证明声明属性与 FIDO 联盟元数据服务中注册的预期值进行
 * verifyJWT();                                    // 对对 FIDO MDS JWT 的轻量级验证(支持EC2和RSA算法);
 * verifyMDSBlob();      // 对 BLOB 进行真实性与完整性验证,并提取其中包含的 FIDO2,该方法会发起网络请求以执行CRL检查等操作;
 * class BaseMetadataService{};                    // 下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * const MetadataService= new BaseMetadataService; // 用于协调与 FIDO 元数据交互的基础服务;
 * ```
 * - 查看定义:{@link AlgSign}、{@link parseJWT}、 {@link algSignToCOSEInfoMap}、{@link verifyAttestationWithMetadata}、
 * {@link verifyJWT}、 {@link verifyMDSBlob}、{@link BaseMetadataService}、{@link MetadataService}
 */
declare module './metadata.js' {
    export * from './metadata.js';
}

// ================================= settings.js =================================
/**
 * ```js
 * // 文件导出内容
 * class BaseSettingsService{};                    // 用于管理各类 attestation 语句格式的根证书;
 * const SettingsService= new BaseSettingsService; // 用于为所有支持的证明声明格式指定可接受的根证书;
 * ```
 * - 查看定义:@see {@link BaseSettingsService}、{@link SettingsService}
 */
declare module './settings.js' {
    export * from './settings.js';
}

/**
 *
 * 模块导出内容：
 * ```js
 * const AlgSign=[];                               // 支持的签名算法数组
 * parseJWT();                                     // 将 JWT 处理为 JavaScript 友好的数据结构
 * const algSignToCOSEInfoMap={};                  // 将 ALG_SIGN 值转换为 COSE 信息
 * verifyAttestationWithMetadata();                // 将身份验证器的证明声明属性与 FIDO 联盟元数据服务中注册的预期值进行
 * verifyJWT();                                    // 对对 FIDO MDS JWT 的轻量级验证(支持EC2和RSA算法);
 * verifyMDSBlob();      // 对 BLOB 进行真实性与完整性验证,并提取其中包含的 FIDO2,该方法会发起网络请求以执行CRL检查等操作;
 * class BaseMetadataService{};                    // 下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * const MetadataService= new BaseMetadataService; // 用于协调与 FIDO 元数据交互的基础服务;
 * class BaseSettingsService{};                    // 用于管理各类 attestation 语句格式的根证书;
 * const SettingsService= new BaseSettingsService; // 用于为所有支持的证明声明格式指定可接受的根证书;
 * ```
 * - 查看定义:{@link AlgSign}、{@link parseJWT}、 {@link algSignToCOSEInfoMap}、{@link verifyAttestationWithMetadata}、
 * {@link verifyJWT}、 {@link verifyMDSBlob}、{@link BaseMetadataService}、{@link MetadataService}、
 * {@link BaseSettingsService}、{@link SettingsService}
 */
declare module './index.js' { }
export * from './metadata.js';
export * from './settings.js';