'use strict';

/**
 * 解析认证器中第 3 和第 4 个比特位所表示的信息：
 *
 * - 凭证是否可在多设备上使用
 * - 凭证是否已备份
 *
 * 无效的配置会抛出 `Error`
 *
 * @param {Object} param0 标志位对象
 * @param {boolean} param0.be 备份资格标志位（Backup Eligibility）
 * @param {boolean} param0.bs 备份状态标志位（Backup State）
 * @returns {{ credentialDeviceType: 'singleDevice' | 'multiDevice', credentialBackedUp: boolean }}
 */
function parseBackupFlags({ be, bs }) {
    const credentialBackedUp = bs;
    let credentialDeviceType = 'singleDevice';
    if (be) credentialDeviceType = 'multiDevice';
    if (credentialDeviceType === 'singleDevice' && credentialBackedUp) throw new InvalidBackupFlags('单设备凭证错误的指示已备份;');
    return { credentialDeviceType, credentialBackedUp };
}

/**
 * 表示备份标志位配置无效的错误类型
 */
class InvalidBackupFlags extends Error {
    constructor(message) {
        super(message), this.name = 'InvalidBackupFlags';
    }
}

// 导出公共 API
module.exports = { parseBackupFlags, InvalidBackupFlags };