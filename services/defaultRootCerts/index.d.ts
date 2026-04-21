import {
    Google_Hardware_Attestation_Root_1, Google_Hardware_Attestation_Root_2, Google_Hardware_Attestation_Root_3,
    Google_Hardware_Attestation_Root_4, GlobalSign_Root_CA, GlobalSign_Root_CA_R3, Apple_WebAuthn_Root_CA
} from './certs.js';

// ================================= android-key.js =================================

/**
 * ```js
 * // 文件导出内容(Google,GlobalSign,apple, 硬件认证根证书)
 * const Google_Hardware_Attestation_Root_1 ='',Google_Hardware_Attestation_Root_2 ='';
 * const Google_Hardware_Attestation_Root_3 ='',Google_Hardware_Attestation_Root_4 ='';
 * const GlobalSign_Root_CA='',GlobalSign_Root_CA_R3='', Apple_WebAuthn_Root_CA='';
 * ```
 * - 查看定义:@see {@link Google_Hardware_Attestation_Root_1}、{@link Google_Hardware_Attestation_Root_2}、
 * {@link Google_Hardware_Attestation_Root_3}、{@link Google_Hardware_Attestation_Root_4}、{@link GlobalSign_Root_CA}、
 * {@link GlobalSign_Root_CA_R3}、{@link Apple_WebAuthn_Root_CA}
 */
declare module './index.js' { }
export * from './certs.js';