/**
 * 当解析备份标志（be/bs）时遇到无效组合抛出的错误（如单设备凭证标记为已备份）;
* - 查看定义:@see {@link InvalidBackupFlags}
 */
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
 * >无效的配置将抛出 `Error`
 * - 查看定义:@see {@link parseBackupFlags}
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