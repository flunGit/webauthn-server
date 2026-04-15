import type { Base64URLString, Uint8Array_ } from '../types/index.js';
import type { COSEALG, COSECRV, COSEKTY } from '../helpers/index.js';

// ================================= mdsTypes.js =================================
/**
 * 元数据服务结构
 * https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
 */
/** */
export type MDSJWTHeader = { alg: string, typ: string, x5c: Base64URLString[] };

export type MDSJWTPayload = {
    legalHeader: string, no: number, nextUpdate: string;
    entries: MetadataBLOBPayloadEntry[];
};

export type MetadataBLOBPayloadEntry = {
    aaid?: string, aaguid?: string;
    attestationCertificateKeyIdentifiers?: string[];
    metadataStatement?: MetadataStatement;
    biometricStatusReports?: BiometricStatusReport[];
    statusReports: StatusReport[];
    timeOfLastStatusChange: string, rogueListURL?: string, rogueListHash?: string;
};

export type BiometricStatusReport = {
    certLevel: number;
    modality: UserVerify;
    effectiveDate?: string;
    certificationDescriptor?: string;
    certificateNumber?: string;
    certificationPolicyVersion?: string;
    certificationRequirementsVersion?: string;
};

export type StatusReport = {
    status: AuthenticatorStatus;
    effectiveDate?: string;
    authenticatorVersion?: number;
    certificate?: string;
    url?: string;
    certificationDescriptor?: string;
    certificateNumber?: string;
    certificationPolicyVersion?: string;
    certificationRequirementsVersion?: string;
};

export type AuthenticatorStatus =
    | 'NOT_FIDO_CERTIFIED' | 'FIDO_CERTIFIED' | 'USER_VERIFICATION_BYPASS' | 'ATTESTATION_KEY_COMPROMISE'
    | 'USER_KEY_REMOTE_COMPROMISE' | 'USER_KEY_PHYSICAL_COMPROMISE' | 'UPDATE_AVAILABLE' | 'REVOKED'
    | 'SELF_ASSERTION_SUBMITTED' | 'FIDO_CERTIFIED_L1' | 'FIDO_CERTIFIED_L1plus' | 'FIDO_CERTIFIED_L2'
    | 'FIDO_CERTIFIED_L2plus' | 'FIDO_CERTIFIED_L3' | 'FIDO_CERTIFIED_L3plus';

/**
 * FIDO 元数据声明规范中定义的类型
 *
 * 参见 https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html
 */
export type CodeAccuracyDescriptor = {
    base: number, minLength: number, maxRetries?: number, blockSlowdown?: number;
};

export type BiometricAccuracyDescriptor = {
    selfAttestedFRR?: number, selfAttestedFAR?: number;
    maxTemplates?: number, maxRetries?: number, blockSlowdown?: number;
};

export type PatternAccuracyDescriptor = {
    minComplexity: number, maxRetries?: number, blockSlowdown?: number;
};

export type VerificationMethodDescriptor = {
    userVerificationMethod: UserVerify;
    caDesc?: CodeAccuracyDescriptor;
    baDesc?: BiometricAccuracyDescriptor;
    paDesc?: PatternAccuracyDescriptor;
};

export type VerificationMethodANDCombinations = VerificationMethodDescriptor[];

export type rgbPaletteEntry = { r: number, g: number, b: number };

export type DisplayPNGCharacteristicsDescriptor = {
    width: number, height: number, bitDepth: number, colorType: number;
    compression: number, filter: number, interlace: number;
    plte?: rgbPaletteEntry[];
};

export type EcdaaTrustAnchor = {
    X: string, Y: string, c: string, sx: string, sy: string, G1Curve: string;
};

export type ExtensionDescriptor = {
    id: string, tag?: number, data?: string, fail_if_unknown: boolean;
};

/**
 * langCode -> 例如 "en-US", "ja-JP" 等
 */
export type AlternativeDescriptions = {
    [langCode: string]: string;
};

export type MetadataStatement = {
    legalHeader?: string, aaid?: string, aaguid?: string;
    attestationCertificateKeyIdentifiers?: string[];
    description: string;
    alternativeDescriptions?: AlternativeDescriptions;
    authenticatorVersion: number;
    protocolFamily: string;
    schema: number, upv: Version[];
    authenticationAlgorithms: AlgSign[];
    publicKeyAlgAndEncodings: AlgKey[];
    attestationTypes: Attestation[];
    userVerificationDetails: VerificationMethodANDCombinations[];
    keyProtection: KeyProtection[];
    isKeyRestricted?: boolean;
    isFreshUserVerificationRequired?: boolean;
    matcherProtection: MatcherProtection[];
    cryptoStrength?: number;
    attachmentHint?: AttachmentHint[];
    tcDisplay: TransactionConfirmationDisplay[];
    tcDisplayContentType?: string;
    tcDisplayPNGCharacteristics?: DisplayPNGCharacteristicsDescriptor[];
    attestationRootCertificates: string[];
    ecdaaTrustAnchors?: EcdaaTrustAnchor[];
    icon?: string;
    supportedExtensions?: ExtensionDescriptor[];
    authenticatorGetInfo?: AuthenticatorGetInfo;
};

/**
 * 其他规范中声明的类型
 */

/**
 * USER_VERIFY
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#user-verification-methods
 */
export type UserVerify =
    | 'presence_internal' | 'fingerprint_internal' | 'passcode_internal' | 'voiceprint_internal'
    | 'faceprint_internal' | 'location_internal' | 'eyeprint_internal' | 'pattern_internal' | 'handprint_internal'
    | 'passcode_external' | 'pattern_external' | 'none' | 'all';

/**
 * ALG_SIGN
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms
 *
 * 此处使用了有用的 TS 模式，以便在 `verifyAttestationWithMetadata.ts` 中的 `algSignToCOSEInfoMap` 中强制要求存在 COSE 信息映射
 */
export type AlgSign = typeof AlgSign[number];
declare const AlgSign: readonly [
    "secp256r1_ecdsa_sha256_raw", "secp256r1_ecdsa_sha256_der",
    "rsassa_pss_sha256_raw", "rsassa_pss_sha256_der",
    "secp256k1_ecdsa_sha256_raw", "secp256k1_ecdsa_sha256_der",
    "rsassa_pss_sha384_raw",
    "rsassa_pkcsv15_sha256_raw",
    "rsassa_pkcsv15_sha384_raw",
    "rsassa_pkcsv15_sha512_raw",
    "rsassa_pkcsv15_sha1_raw",
    "secp384r1_ecdsa_sha384_raw",
    "secp512r1_ecdsa_sha256_raw",
    "ed25519_eddsa_sha512_raw"
];

/**
 * ALG_KEY
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#public-key-representation-formats
 */
export type AlgKey = | 'ecc_x962_raw' | 'ecc_x962_der' | 'rsa_2048_raw' | 'rsa_2048_der' | 'cose';

/**
 * ATTESTATION
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-attestation-types
 */
export type Attestation = | 'basic_full' | 'basic_surrogate' | 'ecdaa' | 'attca' | 'anonca' | 'none';

/**
 * KEY_PROTECTION
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#key-protection-types
 */
export type KeyProtection = | 'software' | 'hardware' | 'tee' | 'secure_element' | 'remote_handle';

/**
 * MATCHER_PROTECTION
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#matcher-protection-types
 */
export type MatcherProtection = | 'software' | 'tee' | 'on_chip';

/**
 * ATTACHMENT_HINT
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-attachment-hints
 */
export type AttachmentHint = | 'internal' | 'external' | 'wired' | 'wireless' | 'nfc' | 'bluetooth' | 'network'
    | 'ready' | 'wifi_direct';

/**
 * TRANSACTION_CONFIRMATION_DISPLAY
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#transaction-confirmation-display-types
 */
export type TransactionConfirmationDisplay = | 'any' | 'privileged_software' | 'tee' | 'hardware' | 'remote';

/**
 * https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface
 */
export type Version = { major: number; minor: number; };

/**
 * https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
 */
export type AuthenticatorGetInfo = {
    versions: ('FIDO_2_0' | 'U2F_V2')[];
    extensions?: string[];
    aaguid: string;
    options?: { plat?: boolean, rk?: boolean, clientPin?: boolean, up?: boolean, uv?: boolean };
    maxMsgSize?: number;
    pinProtocols?: number[];
    algorithms?: { type: 'public-key', alg: number }[];
};

export { };

// ================================= parseJWT.js =================================
/**
 * 将 JWT 处理为 JavaScript 友好的数据结构
 */
export declare function parseJWT<T1, T2>(jwt: string): [T1, T2, string];

// ================================= verifyAttestationWithMetadata.js =================================
/**
 * 将身份验证器的证明声明属性与 FIDO 联盟元数据服务中注册的预期值进行匹配
 */
export declare function verifyAttestationWithMetadata({ statement, credentialPublicKey, x5c, attestationStatementAlg, }: {
    statement: MetadataStatement;
    credentialPublicKey: Uint8Array_;
    x5c: Uint8Array_[] | Base64URLString[];
    attestationStatementAlg?: number;
}): Promise<boolean>;

type COSEInfo = { kty: COSEKTY, alg: COSEALG, crv?: COSECRV };

/**
 * 将 ALG_SIGN 值转换为 COSE 信息
 *
 * 值取自 FIDO 预定义值注册表中的 `ALG_KEY_COSE` 定义
 *
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms
 */
export declare const algSignToCOSEInfoMap: { [key in AlgSign]: COSEInfo };

export { };

// ================================= verifyJWT.js =================================
/**
 * 针对 FIDO MDS JWT 的轻量级验证,支持 EC2 和 RSA 算法;
 *
 * 如果未来需要支持更多 JWS 算法,可参考以下列表：
 *
 * https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1
 *
 * （摘自 https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1）
 */
export declare function verifyJWT(jwt: string, leafCert: Uint8Array_): Promise<boolean>;

// ================================= verifyMDSBlob.js =================================
/**
 * 对符合 [FIDO 元数据服务 (MDS)](https://fidoalliance.org/metadata/) 规范的 JWT ,
 * 并提取其中包含的 FIDO2 ,该方法会发起网络请求以执行 CRL 检查等操作;
 *
 * @param blob - 从 MDS 服务器下载的 JWT 字符串（例如 https://mds3.fidoalliance.org）
 */
export declare function verifyMDSBlob(blob: string): Promise<{
    statements: MetadataStatement[]; // 已验证数据块中包含的 MetadataStatement 条目列表
    parsedNextUpdate: Date;          // 已验证数据块的 `nextUpdate` 字段值,表示该数据块的过期时间
    payload: MDSJWTPayload;          // 已验证数据块的完整 JWT 载荷对象,包含所有原始字段和数据
}>;