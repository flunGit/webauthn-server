import { isoBase64URL, isoUint8Array, generateChallenge } from '../helpers/index.js';

const { fromBuffer, isBase64URL, trimPadding } = isoBase64URL,
    /**
     * 生成用于身份验证器认证的参数,该参数可直接传递给 `navigator.credentials.get(...)`
     *
     * **选项说明：**
     *
     * @param rpID - 有效的域名（`https://` 之后的部分）
     * @param allowCredentials **（可选）** - 用户之前注册过的身份验证器列表（如有）,如果未提供,客户端将询问用户选择要使用的凭证
     * @param challenge **（可选）** - 随机值，身份验证器需要对其签名并返回以完成用户认证;默认会生成一个随机值
     * @param timeout **（可选）** - 用户完成认证所允许的最长时间（毫秒）,默认为 `60000`
     * @param userVerification **（可选）** - 在作为双因素认证流程的一部分进行断言时设置为 `'discouraged'`
     *  否则根据需要设置为 `'preferred'` 或 `'required'`;默认为 `"preferred"`
     * @param extensions **（可选）** - 身份验证器或浏览器在认证过程中应使用的附加插件/扩展
     */
    generateAuthenticationOptions = async options => {
        const {
            allowCredentials, challenge = await generateChallenge(), timeout = 60000,
            userVerification = 'preferred', extensions, rpID,
        } = options;

        /**
         * 保留对 `string` 类型 challenge 值的支持
         */
        let _challenge = challenge;
        if (typeof _challenge === 'string') _challenge = isoUint8Array.fromUTF8String(_challenge);

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