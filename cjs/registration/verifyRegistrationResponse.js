'use strict';

const { decodeAttestationObject, decodeClientDataJSON, parseAuthenticatorData, decodeCredentialPublicKey, COSEKEYS,
    isoBase64URL, convertAAGUIDToString, parseBackupFlags, matchExpectedRPID, toHash
} = require('../helpers/index.js'), { toBuffer, fromBuffer } = isoBase64URL,
    { SettingsService } = require('../services/settingsService.js'),
    { supportedCOSEAlgorithmIdentifiers } = require('./generateRegistrationOptions.js'),
    { verifyAttestationFIDOU2F } = require('./verifications/verifyAttestationFIDOU2F.js'),
    { verifyAttestationPacked } = require('./verifications/verifyAttestationPacked.js'),
    { verifyAttestationAndroidSafetyNet } = require('./verifications/verifyAttestationAndroidSafetyNet.js'),
    { verifyAttestationTPM } = require('./verifications/tpm/verifyAttestationTPM.js'),
    { verifyAttestationAndroidKey } = require('./verifications/verifyAttestationAndroidKey.js'),
    { verifyAttestationApple } = require('./verifications/verifyAttestationApple.js');

/**
 * 验证用户是否合法完成了注册流程
 *
 * **选项说明：**
 *
 * @param response - 由 **flun-webauthn-browser** 的 `startRegistration()` 返回的响应
 * @param expectedChallenge - `generateRegistrationOptions()` 返回的 base64url 编码的 `options.challenge`
 * @param expectedOrigin - 注册应当发生的网站 URL（或 URL 数组）
 * @param expectedRPID - 注册选项中指定的 RP ID（或 RP ID 数组）
 * @param expectedType （可选）- 期望的响应类型（'webauthn.create'）
 * @param requireUserPresence （可选）- 强制要求用户存在（或在自动注册时跳过）。默认为 `true`
 * @param requireUserVerification （可选）- 强制要求用户验证（通过 PIN、指纹等）。默认为 `true`
 * @param supportedAlgorithmIDs （可选）- RP 支持的用于证明的 COSE 算法标识符数字数组。参见 https://www.iana.org/assignments/cose/cose.xhtml#algorithms。默认为所有支持的算法 ID
 * @param attestationSafetyNetEnforceCTSCheck （可选）- 若使用 SafetyNet 证明，则要求 Android 设备的系统完整性未被篡改。默认为 `true`
 */
async function verifyRegistrationResponse(options) {
    const {
        response, expectedChallenge, expectedOrigin, expectedRPID, expectedType, requireUserPresence = true,
        requireUserVerification = true, supportedAlgorithmIDs = supportedCOSEAlgorithmIdentifiers,
        attestationSafetyNetEnforceCTSCheck = true
    } = options, { id, rawId, type: credentialType, response: attestationResponse } = response;

    // 确保证书指定了 ID
    if (!id) throw new Error('缺少凭证 ID');
    // 确保 ID 是 base64url 编码的
    if (id !== rawId) throw new Error('凭证 ID 不是 base64url 编码格式');
    // 确保凭证类型为 public-key
    if (credentialType !== 'public-key') throw new Error(`意外的凭证类型 "${credentialType}"，期望类型为 "public-key"`);

    const clientDataJSON = decodeClientDataJSON(attestationResponse.clientDataJSON),
        { type, origin, challenge, tokenBinding } = clientDataJSON;

    // 确保正在处理注册操作
    if (Array.isArray(expectedType)) {
        if (!expectedType.includes(type)) {
            const joinedExpectedType = expectedType.join(', ');
            throw new Error(`意外的注册响应类型 "${type}"，期望以下之一：${joinedExpectedType}`);
        }
    } else if (expectedType) {
        if (type !== expectedType) throw new Error(`意外的注册响应类型 "${type}"，期望类型为 "${expectedType}"`);
    }
    else if (type !== 'webauthn.create') throw new Error(`意外的注册响应类型: ${type}`);

    // 确保设备提供了我们给出的挑战值
    if (typeof expectedChallenge === 'function') {
        if (!(await expectedChallenge(challenge)))
            throw new Error(`自定义挑战验证器对注册响应挑战值 "${challenge}" 返回了 false`);
    } else if (challenge !== expectedChallenge)
        throw new Error(`意外的注册响应挑战值 "${challenge}"，期望值为 "${expectedChallenge}"`);

    // 检查来源是否为我们网站
    if (Array.isArray(expectedOrigin)) {
        if (!expectedOrigin.includes(origin))
            throw new Error(`意外的注册响应来源 "${origin}",期望以下之一：${expectedOrigin.join(', ')}`);
    } else {
        if (origin !== expectedOrigin)
            throw new Error(`意外的注册响应来源 "${origin}",期望来源为 "${expectedOrigin}"`);
    }

    if (tokenBinding) {
        if (typeof tokenBinding !== 'object') throw new Error(`TokenBinding 的值意外: "${tokenBinding}"`);
        if (['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0)
            throw new Error(`tokenBinding.status 的值意外: "${tokenBinding.status}"`);
    }

    const attestationObject = toBuffer(attestationResponse.attestationObject),
        decodedAttestationObject = decodeAttestationObject(attestationObject),
        fmt = decodedAttestationObject.get('fmt'), authData = decodedAttestationObject.get('authData'),
        attStmt = decodedAttestationObject.get('attStmt'), parsedAuthData = parseAuthenticatorData(authData),
        { aaguid, rpIdHash, flags, credentialID, counter, credentialPublicKey, extensionsData } = parsedAuthData;

    // 确保响应的 RP ID 属于我们
    let matchedRPID;
    if (expectedRPID) {
        let expectedRPIDs = [];
        if (typeof expectedRPID === 'string') expectedRPIDs = [expectedRPID];
        else expectedRPIDs = expectedRPID;
        matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);
    }

    // 确保用户确实在场
    if (requireUserPresence && !flags.up) throw new Error('要求用户在场，但用户不在场');
    // 若指定则强制用户验证
    if (requireUserVerification && !flags.uv) throw new Error('要求用户验证，但用户未通过验证');
    if (!credentialID) throw new Error('认证器未提供凭证 ID');
    if (!credentialPublicKey) throw new Error('认证器未提供公钥');
    if (!aaguid) throw new Error('注册过程中未包含 AAGUID');

    const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey), alg = decodedPublicKey.get(COSEKEYS.alg);
    if (typeof alg !== 'number') throw new Error('凭证公钥缺少数值类型的 alg');

    // 确保密钥算法属于我们在注册选项中指定的范围
    if (!supportedAlgorithmIDs.includes(alg)) {
        const supported = supportedAlgorithmIDs.join(', ');
        throw new Error(`意外的公钥算法 "${alg}",期望以下之一："${supported}"`);
    }

    const clientDataHash = await toHash(toBuffer(attestationResponse.clientDataJSON)),
        rootCertificates = SettingsService.getRootCertificates({ identifier: fmt, }),
        // 准备传递给具体验证方法的参数
        verifierOpts = {
            aaguid, attStmt, authData, clientDataHash, credentialID,
            credentialPublicKey, rootCertificates, rpIdHash, attestationSafetyNetEnforceCTSCheck,
        };

    /**
     * 仅当 attestation = 'direct' 时才可进行验证
     */
    let verified = false;
    if (fmt === 'fido-u2f') verified = await verifyAttestationFIDOU2F(verifierOpts);
    else if (fmt === 'packed') verified = await verifyAttestationPacked(verifierOpts);
    else if (fmt === 'android-safetynet') verified = await verifyAttestationAndroidSafetyNet(verifierOpts);
    else if (fmt === 'android-key') verified = await verifyAttestationAndroidKey(verifierOpts);
    else if (fmt === 'tpm') verified = await verifyAttestationTPM(verifierOpts);
    else if (fmt === 'apple') verified = await verifyAttestationApple(verifierOpts);
    else if (fmt === 'none') {
        if (attStmt.size > 0) throw new Error('none 格式的证明声明不应包含额外数据');
        verified = true; // 这是最弱的证明格式,无需其他检查
    } else throw new Error(`不支持的证明格式: ${fmt}`);

    if (!verified) return { verified: false };
    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);

    return {
        verified: true,
        registrationInfo: {
            fmt,
            aaguid: convertAAGUIDToString(aaguid),
            credentialType,
            credential: {
                id: fromBuffer(credentialID),
                publicKey: credentialPublicKey,
                counter,
                transports: response.response.transports,
            },
            attestationObject,
            userVerified: flags.uv,
            credentialDeviceType,
            credentialBackedUp,
            origin: clientDataJSON.origin,
            rpID: matchedRPID,
            authenticatorExtensionResults: extensionsData,
        },
    };
}

module.exports = { verifyRegistrationResponse };