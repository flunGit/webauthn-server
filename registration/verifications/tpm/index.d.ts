import { TPM_ST, TPM_ALG, TPM_ECC_CURVE, TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP } from './constants.js';
import { parseCertInfo, parsePubArea } from './parse.js';

// ================================= constants.js =================================
/**
 * ```js
 * // 文件导出内容(TPM结构标签,算法标识符,椭圆曲线,制造商 ID 到厂商名称的映射表,公钥区域曲线 ID 映射)
 * const TPM_ST, TPM_ALG, TPM_ECC_CURVE, TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP;
 * ```
 * - 查看定义:@see {@link TPM_ST}、{@link TPM_ALG}、{@link TPM_ECC_CURVE }、{@link TPM_MANUFACTURERS}、
 * {@link TPM_ECC_CURVE_COSE_CRV_MAP}
 */
declare module './constants.js' {
    export * from './constants.js';
}

// ================================= parse.js =================================
/**
 * ```js
 * // 文件导出内容
 * parseCertInfo(); // 将 TPM 证明的 certInfo 解析为可读的片段
 * parsePubArea();  // 解析 TPM 认证信息中的 pubArea 缓冲区
 * ```
 * - 查看定义:@see {@link parseCertInfo}、{@link parsePubArea}
 */
declare module './parse.js' {
    export * from './parse.js';
}

// ================================= 导出入口 =================================
/**
 * ```js
 * // 模块导出内容:
 *
 * // 常量(TPM结构标签,算法标识符,椭圆曲线,制造商 ID 到厂商名称的映射表,公钥区域曲线 ID 映射)
 * const TPM_ST, TPM_ALG, TPM_ECC_CURVE, TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP;
 *
 * // 函数
 * parseCertInfo(); // 将 TPM 证明的 certInfo 解析为可读的片段
 * parsePubArea();  // 解析 TPM 认证信息中的 pubArea 缓冲区
 * ```
 * - 查看定义:@see {@link TPM_ST}、{@link TPM_ALG}、{@link TPM_ECC_CURVE }、{@link TPM_MANUFACTURERS}、
 * {@link TPM_ECC_CURVE_COSE_CRV_MAP}、{@link parseCertInfo}、{@link parsePubArea}
 */
declare module './index.js' {
    export * from './constants.js';
    export * from './parse.js';
}