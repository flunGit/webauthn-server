import {
    Google_Hardware_Attestation_Root_1, Google_Hardware_Attestation_Root_2, Google_Hardware_Attestation_Root_3,
    Google_Hardware_Attestation_Root_4
} from './android-key.js';
import { GlobalSign_Root_CA } from './android-safetynet.js';
import { Apple_WebAuthn_Root_CA } from './apple.js';
import { GlobalSign_Root_CA_R3 } from './mds.js';

// ================================= android-key.js =================================

/**
 * ```js
 * // 文件导出内容(Google 硬件认证根证书)
 * const Google_Hardware_Attestation_Root_1 ='',Google_Hardware_Attestation_Root_2 ='';
 * const Google_Hardware_Attestation_Root_3 ='',Google_Hardware_Attestation_Root_4 ='';
 * ```
 * - 查看定义:@see {@link Google_Hardware_Attestation_Root_1}、{@link Google_Hardware_Attestation_Root_2}、
 * {@link Google_Hardware_Attestation_Root_3}、{@link Google_Hardware_Attestation_Root_4}
 */
module './android-key.js' {
    export * from './android-key.js';
}

// ================================= android-safetynet.js =================================
/**
 * ```js
 * // 文件导出内容
 * const GlobalSign_Root_CA=''; // GlobalSign 根证书
 * ```
 * - 查看定义:@see {@link GlobalSign_Root_CA}
 */
module './android-safetynet.js' {
    export * from './android-safetynet.js';
}

// ================================= apple.js =================================
/**
 * ```js
 * // 文件导出内容
 * const Apple_WebAuthn_Root_CA=''; // Apple WebAuthn 根证书
 * ```
 * - 查看定义:@see {@link Apple_WebAuthn_Root_CA}
 */
module './apple.js' {
    export * from './apple.js';
}

// ================================= mds.js =================================
/**
 * ```js
 * // 文件导出内容
 * const GlobalSign_Root_CA_R3=''; // GlobalSign 根证书 CA-R3
 * ```
 * - 查看定义:@see {@link GlobalSign_Root_CA_R3}
 */
module './mds.js' {
    export * from './mds.js';
}