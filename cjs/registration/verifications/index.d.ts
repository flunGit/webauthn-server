import type { AttestationFormatVerifierOpts } from '../index.js';


// ================================= verifyAttestationAndroidKey.js =================================
/**
 * 验证格式为 'android-key' 的 attestation 响应
 */
export declare function verifyAttestationAndroidKey(options: AttestationFormatVerifierOpts): Promise<boolean>;

// ================================= verifyAttestationAndroidSafetyNet.js =================================
/**
 * 验证格式为 'android-safetynet' 的证明响应
 */
export declare function verifyAttestationAndroidSafetyNet(options: AttestationFormatVerifierOpts): Promise<boolean>;

// ================================= verifyAttestationApple.js =================================
/**
 * 验证 Apple 类型的证明响应
 */
export declare function verifyAttestationApple(options: AttestationFormatVerifierOpts): Promise<boolean>;

// ================================= verifyAttestationFIDOU2F.js =================================
/**
 * 使用 'fido-u2f' 格式验证认证（Attestation）响应
 */
export declare function verifyAttestationFIDOU2F(options: AttestationFormatVerifierOpts): Promise<boolean>;

// ================================= verifyAttestationPacked.js =================================
/**
 * 验证格式为 'packed' 的 attestation 响应
 */
export declare function verifyAttestationPacked(options: AttestationFormatVerifierOpts): Promise<boolean>;