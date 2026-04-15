import type { Uint8Array_ } from '../../../types/index.js';
import type { AttestationFormatVerifierOpts } from '../../index.js';

// ================================= constants.js =================================
/**
 * 这里汇集了大量领域知识,与源文档的关系较为模糊,若要深入了解这些值的更多信息,建议查阅以下
 * WebAuthn API 引用的 Trusted Computing Group TPM 库文档：
 *
 * - https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
 * - https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
 * - https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
 */

/**
 * 6.9 TPM_ST（结构标签）
 */
export declare const TPM_ST: { [key: number]: string };

/**
 * 6.3 TPM_ALG_ID
 */
export declare const TPM_ALG: { [key: number]: string };

/**
 * 6.4 TPM_ECC_CURVE
 */
export declare const TPM_ECC_CURVE: { [key: number]: string };

type ManufacturerInfo = { name: string, id: string };

/**
 * 数据来源：https://trustedcomputinggroup.org/resource/vendor-id-registry/
 *
 * 最新版本：
 * https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.02-Revision-1.00.pdf
 */
export declare const TPM_MANUFACTURERS: { [key: string]: ManufacturerInfo };

/**
 * 将 TPM 公钥区曲线 ID 映射到 COSE 公钥中使用的 `crv` 数值
 */
export declare const TPM_ECC_CURVE_COSE_CRV_MAP: { [key: string]: number };

export { };

// ================================= parseCertInfo.js =================================
/**
 * 将 TPM 证明的 certInfo 解析为可读的片段
 */
export declare function parseCertInfo(certInfo: Uint8Array_): ParsedCertInfo;

type ParsedCertInfo = {
    magic: number;
    type: string;
    qualifiedSigner: Uint8Array_, extraData: Uint8Array_;
    clockInfo: {
        clock: Uint8Array_;
        resetCount: number, restartCount: number;
        safe: boolean;
    };
    firmwareVersion: Uint8Array_;
    attested: {
        nameAlg: string;
        nameAlgBuffer: Uint8Array_, name: Uint8Array_, qualifiedName: Uint8Array_;
    };
};
export { };

// ================================= parsePubArea.js =================================
/**
 * 解析 TPM 认证信息中的 pubArea 缓冲区
 *
 * 参考文档：12.2.4 节 TPMT_PUBLIC,链接如下：
 * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
 */
export declare function parsePubArea(pubArea: Uint8Array_): ParsedPubArea;

type ParsedPubArea = {
    type: 'TPM_ALG_RSA' | 'TPM_ALG_ECC';
    nameAlg: string;
    objectAttributes: {
        fixedTPM: boolean, stClear: boolean, fixedParent: boolean, sensitiveDataOrigin: boolean, userWithAuth: boolean;
        adminWithPolicy: boolean, noDA: boolean, encryptedDuplication: boolean, restricted: boolean, decrypt: boolean;
        signOrEncrypt: boolean;
    };
    authPolicy: Uint8Array_;
    parameters: { rsa?: RSAParameters, ecc?: ECCParameters };
    unique: Uint8Array_;
};

type RSAParameters = {
    symmetric: string, scheme: string;
    keyBits: number, exponent: number;
};

type ECCParameters = { symmetric: string, scheme: string, curveID: string, kdf: string };

export { };

// ================================= verifyAttestationTPM.js =================================
export declare function verifyAttestationTPM(options: AttestationFormatVerifierOpts): Promise<boolean>;