import { verifyAttestationAndroidKey } from './verifyAttestationAndroidKey.js';
import { verifyAttestationAndroidSafetyNet } from './verifyAttestationAndroidSafetyNet.js';
import { verifyAttestationApple } from './verifyAttestationApple.js';
import { verifyAttestationFIDOU2F } from './verifyAttestationFIDOU2F.js';
import { verifyAttestationPacked } from './verifyAttestationPacked.js';
import { verifyAttestationTPM } from './verifyAttestationTPM.js';

// ================================= verifyAttestationAndroidKey.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationAndroidKey(); // 验证格式为 'android-key' 的 attestation 响应
 * ```
 * - 查看定义:@see {@link verifyAttestationAndroidKey}
 */
declare module './verifyAttestationAndroidKey.js' {
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
declare module './verifyAttestationAndroidSafetyNet.js' {
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
declare module './verifyAttestationApple.js' {
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
declare module './verifyAttestationFIDOU2F.js' {
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
declare module './verifyAttestationPacked.js' {
    export * from './verifyAttestationPacked.js';
}

// ================================= verifyAttestationTPM.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAttestationTPM(); // 验证TPM认证器返回的attestation陈述,确保其符合 FIDO2 规范
 * ```
 * - 查看定义:@see {@link verifyAttestationTPM}
 */
declare module './verifyAttestationTPM.js' {
    export * from './verifyAttestationTPM.js';
}

// ================================= 导出入口 =================================
/**
 * ```js
 * // 模块导出内容:
 * verifyAttestationAndroidKey();       // 验证格式为 'android-key' 的 attestation 响应
 * verifyAttestationAndroidSafetyNet(); // 验证格式为 'android-safetynet' 的证明响应
 * verifyAttestationApple();            // 验证 Apple 类型的证明响应
 * verifyAttestationFIDOU2F();          // 使用 'fido-u2f' 格式验证认证（Attestation）响应
 * verifyAttestationPacked();           // 验证格式为 'packed' 的 attestation 响应
 * verifyAttestationTPM(); // 验证TPM认证器返回的attestation陈述,确保其符合 FIDO2 规范
 * ```
 * - 查看定义:@see {@link verifyAttestationAndroidKey}、{@link verifyAttestationAndroidSafetyNet}、
 * {@link verifyAttestationApple}、{@link verifyAttestationFIDOU2F}、{@link verifyAttestationPacked}、
 * {@link verifyAttestationTPM}
 */
declare module './index.js' { }
export * from './verifyAttestationAndroidKey.js';
export * from './verifyAttestationAndroidSafetyNet.js';
export * from './verifyAttestationApple.js';
export * from './verifyAttestationFIDOU2F.js';
export * from './verifyAttestationPacked.js';
export * from './verifyAttestationTPM.js';