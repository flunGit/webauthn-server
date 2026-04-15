class InvalidBackupFlags extends Error {
    constructor(message) {
        super(message), this.name = 'InvalidBackupFlags';
    }
}
/**
 * 解析身份验证器返回的比特位 3 和 4,用于判断：
 *
 * - 凭证是否可以在多设备上使用
 * - 凭证是否已备份
 *
 * 无效的配置将抛出 `Error`
 */
const parseBackupFlags = ({ be, bs }) => {
    const credentialBackedUp = bs;
    let credentialDeviceType = 'singleDevice';
    if (be) credentialDeviceType = 'multiDevice';
    if (credentialDeviceType === 'singleDevice' && credentialBackedUp)
        throw new InvalidBackupFlags('单设备凭证指示其已被备份,这应该是不可能的;请检查您的身份验证器是否正确实现了规范');
    return { credentialDeviceType, credentialBackedUp };
};

export { parseBackupFlags, InvalidBackupFlags };