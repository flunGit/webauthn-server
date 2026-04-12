'use strict';

// 导入依赖（解构所需导出）
const { convertCertBufferToPEM } = require('../helpers/convertCertBufferToPEM.js'),
    {
        Google_Hardware_Attestation_Root_1, Google_Hardware_Attestation_Root_2,
        Google_Hardware_Attestation_Root_3, Google_Hardware_Attestation_Root_4
    } = require('./defaultRootCerts/android-key.js'),
    { GlobalSign_Root_CA } = require('./defaultRootCerts/android-safetynet.js'),
    { Apple_WebAuthn_Root_CA } = require('./defaultRootCerts/apple.js'),
    { GlobalSign_Root_CA_R3 } = require('./defaultRootCerts/mds.js');

/**
 * 内部基础设置服务类
 */
class BaseSettingsService {
    pemCertificates = new Map(); // 证书存储为 PEM 格式字符串的 Map

    /**
     * 设置指定标识符的根证书列表
     * @param {Object} opts - 配置项
     * @param {string} opts.identifier - 证书格式标识符
     * @param {Array<Uint8Array|string>} opts.certificates - 证书列表（Uint8Array 或 PEM 字符串）
     */
    setRootCertificates({ identifier, certificates }) {
        const newCertificates = [];
        for (const cert of certificates) {
            if (cert instanceof Uint8Array) newCertificates.push(convertCertBufferToPEM(cert));
            else newCertificates.push(cert);
        }
        this.pemCertificates.set(identifier, newCertificates);
    }

    /**
     * 获取指定标识符的根证书列表
     * @param {Object} opts - 配置项
     * @param {string} opts.identifier - 证书格式标识符
     * @returns {Array<string>} PEM 格式的证书数组
     */
    getRootCertificates({ identifier }) {
        return this.pemCertificates.get(identifier) ?? [];
    }
}

/**
 * 为所有支持的认证声明格式提供可接受的根证书配置服务。
 *
 * 此外，以下声明格式默认包含了内置的根证书：
 *
 * - `'android-key'`
 * - `'android-safetynet'`
 * - `'apple'`
 * - `'mds'`
 *
 * 如果需要替换这些根证书，可以使用 `setRootCertificates()` 方法为对应的格式标识符设置替代的根证书。
 */
const SettingsService = new BaseSettingsService();

// 初始化默认证书
SettingsService.setRootCertificates({
    identifier: 'android-key',
    certificates: [
        Google_Hardware_Attestation_Root_1, Google_Hardware_Attestation_Root_2,
        Google_Hardware_Attestation_Root_3, Google_Hardware_Attestation_Root_4
    ],
});
SettingsService.setRootCertificates({ identifier: 'android-safetynet', certificates: [GlobalSign_Root_CA] });
SettingsService.setRootCertificates({ identifier: 'apple', certificates: [Apple_WebAuthn_Root_CA] });
SettingsService.setRootCertificates({ identifier: 'mds', certificates: [GlobalSign_Root_CA_R3] });

// 导出公共 API
module.exports = { SettingsService, BaseSettingsService };