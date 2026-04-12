'use strict';

/**
 * 生成 WebAuthn 注册选项（用于 navigator.credentials.create）
 */
const { isoBase64URL, isoUint8Array, generateChallenge, generateUserID } = require('../helpers/index.js'),
    { fromBuffer, isBase64URL, trimPadding } = isoBase64URL,
    /**
     * 支持的 COSE 算法标识符
     * 参见 https://w3c.github.io/webauthn/#sctn-alg-identifier
     * 以及 https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     */
    supportedCOSEAlgorithmIdentifiers = [
        -8,   // EdDSA（置于首位以鼓励认证器优先选用）
        -7,   // ECDSA 配合 SHA-256
        -36,  // ECDSA 配合 SHA-512
        -37,  // RSASSA-PSS 配合 SHA-256
        -38,  // RSASSA-PSS 配合 SHA-384
        -39,  // RSASSA-PSS 配合 SHA-512
        -257, // RSASSA-PKCS1-v1_5 配合 SHA-256
        -258, // RSASSA-PKCS1-v1_5 配合 SHA-384
        -259, // RSASSA-PKCS1-v1_5 配合 SHA-512
        -65535, // RSASSA-PKCS1-v1_5 配合 SHA-1（已弃用；保留以支持旧环境）
    ],

    /**
     * 根据最新规范设置一些默认的认证器选择选项：
     * https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
     *
     * 这有助于兼容一些可能不了解这些默认值的旧平台（例如 Android 7.0 Nougat）
     */
    defaultAuthenticatorSelection = { residentKey: 'preferred', userVerification: 'preferred' },

    /**
     * 使用最广泛支持的算法
     * 参见：
     *   - https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     *   - https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams
     */
    defaultSupportedAlgorithmIDs = [-8, -7, -257];

/**
 * 准备用于 navigator.credentials.create(...) 的认证器注册选项值
 *
 * @param {Object} options - 配置选项
 * @param {string} options.rpName - 面向用户的、友好的网站/服务名称
 * @param {string} options.rpID - 有效域名（`https://` 之后的部分）
 * @param {string} options.userName - 用户在网站中的用户名（如邮箱等）
 * @param {Uint8Array|string} [options.userID] - 用户在网站中的唯一标识符。默认自动生成一个随机 ID
 * @param {Uint8Array|string} [options.challenge] - 认证器需要签名并回传的随机值。默认自动生成
 * @param {string} [options.userDisplayName=''] - 用户的真实姓名
 * @param {number} [options.timeout=60000] - 用户完成认证的时间上限（毫秒）
 * @param {string} [options.attestationType='none'] - 特定的证明声明格式
 * @param {Array} [options.excludeCredentials=[]] - 用户已注册的认证器列表，用于防止重复注册
 * @param {Object} [options.authenticatorSelection] - 限制可用认证器类型的高级条件。默认为 `{ residentKey: 'preferred', userVerification: 'preferred' }`
 * @param {Object} [options.extensions] - 在认证过程中浏览器或认证器应启用的附加插件
 * @param {number[]} [options.supportedAlgorithmIDs] - 本 RP 支持的一系列 COSE 算法标识符。默认 `[-8, -7, -257]`
 * @param {string} [options.preferredAuthenticatorType] - 鼓励浏览器引导用户注册特定类型的认证器（`securityKey`、`localDevice` 或 `remoteDevice`）
 * @returns {Promise<Object>} PublicKeyCredentialCreationOptions 对象
 */
async function generateRegistrationOptions(options) {
    const {
        rpName, rpID, userName, userID, challenge = await generateChallenge(), userDisplayName = '', timeout = 60000,
        attestationType = 'none', excludeCredentials = [], authenticatorSelection = defaultAuthenticatorSelection,
        extensions, supportedAlgorithmIDs = defaultSupportedAlgorithmIDs, preferredAuthenticatorType,
    } = options, pubKeyCredParams = supportedAlgorithmIDs.map(id => ({ alg: id, type: 'public-key' }));

    // 处理 `residentKey` 和 `requireResidentKey` 的细微差别,以符合 WebAuthn 规范
    if (authenticatorSelection.residentKey === undefined) {
        // `residentKey` 未定义时,若 `requireResidentKey` 为 true 则等效值为 `required`,否则为 `discouraged`
        // 参考 https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey
        if (authenticatorSelection.requireResidentKey) authenticatorSelection.residentKey = 'required';
        // 注意：虽然规范允许设为 `discouraged`,但为了通过某些合规性测试，此处暂不自动赋值
    } else
        // `requireResidentKey` 应当与 `residentKey === 'required'` 保持一致
        // 参考 https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
        authenticatorSelection.requireResidentKey = authenticatorSelection.residentKey === 'required';

    // 确保 challenge 为 Uint8Array 类型（允许传入字符串并转为 UTF-8 字节）
    let _challenge = challenge;
    if (typeof _challenge === 'string') _challenge = isoUint8Array.fromUTF8String(_challenge);
    // 明确禁止使用字符串形式的 userID,因为后续 `isoBase64URL.fromBuffer()` 若收到字符串会返回空值
    if (typeof userID === 'string') throw new Error('不再支持使用字符串作为 userID;');

    // 若未提供 userID，则生成一个新的
    let _userID = userID;
    if (!_userID) _userID = await generateUserID();

    // 将认证器偏好类型映射为 hints 字段，并同时设置 authenticatorAttachment 以保持向后兼容
    const hints = [];
    if (preferredAuthenticatorType) {
        if (preferredAuthenticatorType === 'securityKey')
            hints.push('security-key'), authenticatorSelection.authenticatorAttachment = 'cross-platform';
        else if (preferredAuthenticatorType === 'localDevice')
            hints.push('client-device'), authenticatorSelection.authenticatorAttachment = 'platform';
        else if (preferredAuthenticatorType === 'remoteDevice')
            hints.push('hybrid'), authenticatorSelection.authenticatorAttachment = 'cross-platform';
    }

    // 构建并返回最终的 PublicKeyCredentialCreationOptions 对象
    return {
        challenge: fromBuffer(_challenge),
        rp: { name: rpName, id: rpID },
        user: { id: fromBuffer(_userID), name: userName, displayName: userDisplayName },
        pubKeyCredParams,
        timeout,
        attestation: attestationType,
        excludeCredentials: excludeCredentials.map((cred) => {
            if (!isBase64URL(cred.id)) throw new Error(`排除凭据中的 id "${cred.id}" 不是有效的 base64url 字符串`);
            return { ...cred, id: trimPadding(cred.id), type: 'public-key' };
        }),
        authenticatorSelection,
        extensions: { ...extensions, credProps: true },
        hints,
    };
}

// 导出公共 API
module.exports = { supportedCOSEAlgorithmIdentifiers, generateRegistrationOptions };