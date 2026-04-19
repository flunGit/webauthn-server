import { TPM_ST, TPM_ALG, TPM_ECC_CURVE, TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP } from './constants.js';
import { parseCertInfo } from './parseCertInfo.js';
import { parsePubArea } from './parsePubArea.js';
import { verifyAttestationTPM } from './verifyAttestationTPM.js';

// ================================= constants.js =================================
/**
 * ```js
 * // 文件导出内容(TPM结构标签,算法标识符,椭圆曲线,制造商 ID 到厂商名称的映射表,公钥区域曲线 ID 映射)
 * const TPM_ST, TPM_ALG, TPM_ECC_CURVE, TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP;
 * ```
 * - 查看定义:@see {@link TPM_ST}、{@link TPM_ALG}、{@link TPM_ECC_CURVE }、{@link TPM_MANUFACTURERS}、
 * {@link TPM_ECC_CURVE_COSE_CRV_MAP}
 */
module './constants.js' {
    export * from './constants.js';
}

// ================================= parseCertInfo.js =================================
/**
 * ```js
 * // 文件导出内容
 * parseCertInfo(); // 将 TPM 证明的 certInfo 解析为可读的片段
 * ```
 * - 查看定义:@see {@link parseCertInfo}
 */
module './parseCertInfo.js' {
    export * from './parseCertInfo.js';
}

// ================================= parsePubArea.js =================================
/**
 * ```js
 * // 文件导出内容
 * parsePubArea(); // 解析 TPM 认证信息中的 pubArea 缓冲区
 * ```
 * - 查看定义:@see {@link parsePubArea}
 */
module './parsePubArea.js' {
    export * from './parsePubArea.js';
}

// ================================= verifyAttestationTPM.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationTPM(); // 验证 TPM 认证器返回的 attestation 陈述,确保其符合 FIDO2 规范
 * ```
 * - 查看定义:@see {@link verifyAttestationTPM}
 */
module './verifyAttestationTPM.js' {
    export * from './verifyAttestationTPM.js';
}