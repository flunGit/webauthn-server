import { fromBuffer, isBase64URL, trimPadding, utf8Tobytes, generateChallenge } from '../helpers/index.js';

/**
 * 生成用于身份验证器认证的参数
 * - 查看定义:@see {@link generateAuthenticationOptions}
 * @param {Object} options - 配置选项
 * @param {string} options.rpID - 有效的域名（`https://` 之后的部分）
 * @param {BufferSource} [options.challenge] - 随机挑战值
 * @param {PublicKeyCredentialDescriptor[]} [options.allowCredentials] - 之前注册过的凭证列表
 * @param {number} [options.timeout] - 超时毫秒数，默认 60000
 * @param {UserVerificationRequirement} [options.userVerification] - 用户验证要求
 * @param {AuthenticationExtensionsClientInputs} [options.extensions] - 扩展项
 * @returns {Promise<{
 *   rpId: string,
 *   challenge: string,
 *   allowCredentials: PublicKeyCredentialDescriptor[],
 *   timeout: number,
 *   userVerification: UserVerificationRequirement,
 *   extensions: AuthenticationExtensionsClientInputs
 * }>}
 */
const generateAuthenticationOptions = async options => {
    const {
        allowCredentials, challenge = await generateChallenge(), timeout = 60000,
        userVerification = 'preferred', extensions, rpID,
    } = options;

    /**
     * 保留对 `string` 类型 challenge 值的支持
     */
    let _challenge = challenge;
    if (typeof _challenge === 'string') _challenge = utf8Tobytes(_challenge);

    return {
        rpId: rpID,
        challenge: fromBuffer(_challenge),
        allowCredentials: allowCredentials?.map(cred => {
            if (!isBase64URL(cred.id)) throw new Error(`allowCredential id "${cred.id}"不是合法的base64url字符串`);

            return { ...cred, id: trimPadding(cred.id), type: 'public-key', };
        }),
        timeout, userVerification, extensions
    };
};

export { generateAuthenticationOptions };