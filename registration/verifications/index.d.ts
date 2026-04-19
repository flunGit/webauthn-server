import type { AttestationFormatVerifierOpts } from '../index.js';

import type { verifyAttestationAndroidKey } from './verifyAttestationAndroidKey.js';
import type { verifyAttestationAndroidSafetyNet } from './verifyAttestationAndroidSafetyNet.js';
import type { verifyAttestationApple } from './verifyAttestationApple.js';
import type { verifyAttestationFIDOU2F } from './verifyAttestationFIDOU2F.js';
import type { verifyAttestationPacked } from './verifyAttestationPacked.js';
// ================================= verifyAttestationAndroidKey.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationAndroidKey(); // 验证格式为 'android-key' 的 attestation 响应
 * ```
 * - 查看定义:@see {@link verifyAttestationAndroidKey}
 */
module './verifyAttestationAndroidKey.js' {
    export * from './verifyAttestationAndroidKey.js';
}

// ================================= verifyAttestationAndroidSafetyNet.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationAndroidSafetyNet(); // 验证格式为 'android-safetynet' 的证明响应
 * ```
 * - 查看定义:@see {@link verifyAttestationAndroidSafetyNet}
 */
module './verifyAttestationAndroidSafetyNet.js' {
    export * from './verifyAttestationAndroidSafetyNet.js';
}

// ================================= verifyAttestationApple.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationApple(); // 验证 Apple 类型的证明响应
 * ```
 * - 查看定义:@see {@link verifyAttestationApple}
 */
module './verifyAttestationApple.js' {
    export * from './verifyAttestationApple.js';
}

// ================================= verifyAttestationFIDOU2F.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationFIDOU2F(); // 使用 'fido-u2f' 格式验证认证（Attestation）响应
 * ```
 * - 查看定义:@see {@link verifyAttestationFIDOU2F}
 */
module './verifyAttestationFIDOU2F.js' {
    export * from './verifyAttestationFIDOU2F.js';
}

// ================================= verifyAttestationPacked.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationPacked(); // 验证格式为 'packed' 的 attestation 响应
 * ```
 * - 查看定义:@see {@link verifyAttestationPacked}
 */
module './verifyAttestationPacked.js' {
    export * from './verifyAttestationPacked.js';
}