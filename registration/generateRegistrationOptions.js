import { isoBase64URL, isoUint8Array, generateChallenge, generateUserID } from '../helpers/index.js';

const { fromBuffer, isBase64URL, trimPadding } = isoBase64URL,
    /**
     * 支持的加密算法标识符
     * 参见 https://w3c.github.io/webauthn/#sctn-alg-identifier
     * 以及 https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     */
    supportedCOSEAlgorithmIdentifiers = [
        // EdDSA（放在首位以鼓励验证器优先使用此算法而非 ES256）
        -8,
        // 带 SHA-256 的 ECDSA
        -7,
        // 带 SHA-512 的 ECDSA
        -36,
        // 带 SHA-256 的 RSASSA-PSS
        -37,
        // 带 SHA-384 的 RSASSA-PSS
        -38,
        // 带 SHA-512 的 RSASSA-PSS
        -39,
        // 带 SHA-256 的 RSASSA-PKCS1-v1_5
        -257,
        // 带 SHA-384 的 RSASSA-PKCS1-v1_5
        -258,
        // 带 SHA-512 的 RSASSA-PKCS1-v1_5
        -259,
        // 带 SHA-1 的 RSASSA-PKCS1-v1_5（已弃用，仅为遗留支持）
        -65535,
    ],

    /**
     * 根据最新规范设置默认的身份验证器选择选项：
     * https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
     *
     * 有助于某些旧平台（例如 Android 7.0 Nougat）了解这些默认值;
     */
    defaultAuthenticatorSelection = { residentKey: 'preferred', userVerification: 'preferred' },

    /**
     * 使用最广泛支持的算法
     * 参见：
     *   - https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     *   - https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams
     */
    defaultSupportedAlgorithmIDs = [-8, -7, -257],

    /**
     * 生成用于身份验证器注册的参数,该参数可直接传递给 `navigator.credentials.create(...)`
     *
     * **选项说明：**
     *
     * @param rpName - 用户可见的、“友好”的网站/服务名称
     * @param rpID - 有效的域名（`https://` 之后的部分）
     * @param userName - 用户在此网站上的用户名（邮箱等）
     * @param userID **（可选）** - 用户在此网站上的唯一标识符,默认生成一个随机标识符
     * @param challenge **（可选）** - 随机值，身份验证器需要对其签名并返回。默认生成一个随机值
     * @param userDisplayName **（可选）** - 用户的真实姓名,默认为 `""`
     * @param timeout **（可选）** - 用户完成认证所允许的最长时间（毫秒）。默认为 `60000`
     * @param attestationType **（可选）** - 具体的证明声明类型,默认为 `"none"`
     * @param excludeCredentials **（可选）** - 用户已注册的身份验证器列表,防止同一凭证被重复注册,默认为 `[]`
     * @param authenticatorSelection **（可选）** - 用于限制可使用验证器类型的进阶条件,
     * 默认为 `{ residentKey: 'preferred', userVerification: 'preferred' }`
     * @param extensions **（可选）** - 身份验证器或浏览器在证明过程中应使用的附加插件/扩展
     * @param supportedAlgorithmIDs **（可选）** - 当前依赖方支持的用于证明的 COSE 算法标识符数组,
     * 参见 https://www.iana.org/assignments/cose/cose.xhtml#algorithms,默认为 `[-8, -7, -257]`
     * @param preferredAuthenticatorType **（可选）** - 建议浏览器提示用户注册特定类型的身份验证器
     */
    generateRegistrationOptions = async options => {
        const {
            rpName, rpID, userName, userID, challenge = await generateChallenge(),
            userDisplayName = '', timeout = 60000, attestationType = 'none', excludeCredentials = [],
            authenticatorSelection = defaultAuthenticatorSelection, extensions,
            supportedAlgorithmIDs = defaultSupportedAlgorithmIDs, preferredAuthenticatorType,
        } = options,
            /**
             * 根据算法 ID 数组构建 pubKeyCredParams
             */
            pubKeyCredParams = supportedAlgorithmIDs.map(id => ({ alg: id, type: 'public-key' }));

        /**
         * 处理 `residentKey` 与 `requireResidentKey` 的设置细节
         * 根据选项中的定义来配置两者
         */
        if (authenticatorSelection.residentKey === undefined) {
            /**
             * `residentKey`：“如果未提供值，则有效值为：若 requireResidentKey 为 true 则为 `required`，
             * 若为 false 或未提供则为 `discouraged`;”
             *
             * 参见 https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey
             */
            if (authenticatorSelection.requireResidentKey) authenticatorSelection.residentKey = 'required';
            else {
                /**
                 * FIDO Conformance v1.7.2 在以下设置下会失败第一个测试,尽管这在技术上符合 WebAuthn L2 规范……
                 */
                // authenticatorSelection.residentKey = 'discouraged';
            }
        } else {
            /**
             * `requireResidentKey`：“依赖方应仅当 residentKey 设置为 `"required"` 时才将其设为 true”
             *
             * 规范说明此属性默认为 `false`,因此将其赋值为 `false` 也是可以的
             *
             * 参见 https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
             */
            authenticatorSelection.requireResidentKey = authenticatorSelection.residentKey === 'required';
        }

        /**
         * 保留对字符串类型 challenge 的支持
         */
        let _challenge = challenge;
        if (typeof _challenge === 'string') _challenge = isoUint8Array.utf8Tobytes(_challenge);

        /**
         * 显式禁止再使用字符串类型的 userID,因为下面的 `isoBase64URL.fromBuffer()` 会在字符串传入时返回空字符串！
         */
        if (typeof userID === 'string') throw new Error('不再支持使用字符串类型的 `userID`;');

        /**
         * 如果未提供 userID，则生成一个
         */
        let _userID = userID;
        if (!_userID) _userID = await generateUserID();

        /**
         * 将首选身份验证器类型映射到 hints 数组，同时为了向后兼容也映射到 authenticatorAttachment
         */
        const hints = [];
        if (preferredAuthenticatorType) {
            if (preferredAuthenticatorType === 'securityKey')
                hints.push('security-key'), authenticatorSelection.authenticatorAttachment = 'cross-platform';
            else if (preferredAuthenticatorType === 'localDevice')
                hints.push('client-device'), authenticatorSelection.authenticatorAttachment = 'platform';
            else if (preferredAuthenticatorType === 'remoteDevice')
                hints.push('hybrid'), authenticatorSelection.authenticatorAttachment = 'cross-platform';
        }

        return {
            challenge: fromBuffer(_challenge),
            rp: { name: rpName, id: rpID },
            user: { id: fromBuffer(_userID), name: userName, displayName: userDisplayName },
            pubKeyCredParams,
            timeout,
            attestation: attestationType,
            excludeCredentials: excludeCredentials.map((cred) => {
                if (!isBase64URL(cred.id))
                    throw new Error(`excludeCredential 的 id “${cred.id}” 不是合法的 base64url 字符串`);
                return { ...cred, id: trimPadding(cred.id), type: 'public-key' };
            }),
            authenticatorSelection,
            extensions: { ...extensions, credProps: true },
            hints,
        };
    };

export { supportedCOSEAlgorithmIdentifiers, generateRegistrationOptions };