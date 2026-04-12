import {
    decodeAttestationObject, decodeClientDataJSON, parseAuthenticatorData, decodeCredentialPublicKey, COSEKEYS,
    isoBase64URL, convertAAGUIDToString, parseBackupFlags, matchExpectedRPID, toHash
} from '../helpers/index.js';
import { SettingsService } from '../services/settingsService.js';
import { supportedCOSEAlgorithmIdentifiers } from './generateRegistrationOptions.js';
import { verifyAttestationFIDOU2F } from './verifications/verifyAttestationFIDOU2F.js';
import { verifyAttestationPacked } from './verifications/verifyAttestationPacked.js';
import { verifyAttestationAndroidSafetyNet } from './verifications/verifyAttestationAndroidSafetyNet.js';
import { verifyAttestationTPM } from './verifications/tpm/verifyAttestationTPM.js';
import { verifyAttestationAndroidKey } from './verifications/verifyAttestationAndroidKey.js';
import { verifyAttestationApple } from './verifications/verifyAttestationApple.js';

const { toBuffer, fromBuffer } = isoBase64URL;
/**
 * 验证用户是否合法完成了注册流程
 *
 * **选项说明：**
 *
 * @param response - `flun-webauthn-browser` 的 `startAuthentication()` 返回的响应对象
 * @param expectedChallenge - `generateRegistrationOptions()` 返回的 `options.challenge` 的 base64url 编码值
 * @param expectedOrigin - 注册应发生的网站 URL（或 URL 数组）
 * @param expectedRPID - 注册选项中指定的 RP ID（或 ID 数组）
 * @param expectedType **（可选）** - 期望的响应类型（'webauthn.create'）
 * @param requireUserPresence **（可选）** - 强制要求身份验证器验证用户存在（或在自动注册时跳过）,默认为 `true`
 * @param requireUserVerification **（可选）** - 强制要求身份验证器验证用户（通过 PIN、指纹等）,默认为 `true`
 * @param supportedAlgorithmIDs **（可选）** - 本 RP 支持的用于证明的 COSE 算法标识符数值数组,
 * 参见 https://www.iana.org/assignments/cose/cose.xhtml#algorithms。默认为所有支持的算法 ID
 * @param attestationSafetyNetEnforceCTSCheck **（可选）** - 如果使用 SafetyNet 证明,要求 Android 设备的系统完整性未被篡改,默认为 `true`
 */
async function verifyRegistrationResponse(options) {
    const { response, expectedChallenge, expectedOrigin, expectedRPID, expectedType, requireUserPresence = true,
        requireUserVerification = true, supportedAlgorithmIDs = supportedCOSEAlgorithmIdentifiers,
        attestationSafetyNetEnforceCTSCheck = true, } = options,
        { id, rawId, type: credentialType, response: attestationResponse } = response;

    // 确保凭证指定了 ID
    if (!id) throw new Error('缺少凭证 ID');
    // 确保 ID 是 base64url 编码的
    if (id !== rawId) throw new Error('凭证 ID 不是 base64url 编码');
    // 确保凭证类型是 public-key
    if (credentialType !== 'public-key') throw new Error(`意外的凭证类型 ${credentialType},期望 "public-key"`);

    const clientDataJSON = decodeClientDataJSON(attestationResponse.clientDataJSON),
        { type, origin, challenge, tokenBinding } = clientDataJSON;

    // 确保我们正在处理注册操作
    if (Array.isArray(expectedType)) {
        if (!expectedType.includes(type)) {
            const joinedExpectedType = expectedType.join(', ');
            throw new Error(`意外的注册响应类型 "${type}",期望为以下之一：${joinedExpectedType}`);
        }
    } else if (expectedType) {
        if (type !== expectedType) throw new Error(`意外的注册响应类型 "${type}",期望 "${expectedType}"`);
    }
    else if (type !== 'webauthn.create') throw new Error(`意外的注册响应类型：${type}`);

    // 确保设备提供了我们给出的挑战值
    if (typeof expectedChallenge === 'function') {
        if (!(await expectedChallenge(challenge))) throw new Error(`自定义挑战值验证器对注册响应 "${challenge}" 返回了 false`);
    } else if (challenge !== expectedChallenge)
        throw new Error(`意外的注册响应挑战值 "${challenge}",期望 "${expectedChallenge}"`);

    // 检查来源是否为本网站
    if (Array.isArray(expectedOrigin)) {
        if (!expectedOrigin.includes(origin))
            throw new Error(`意外的注册响应来源 "${origin}",期望为以下之一：${expectedOrigin.join(', ')}`);
    } else {
        if (origin !== expectedOrigin) throw new Error(`意外的注册响应来源 "${origin}",期望 "${expectedOrigin}"`);
    }

    if (tokenBinding) {
        if (typeof tokenBinding !== 'object') throw new Error(`TokenBinding 的值意外："${tokenBinding}"`);
        if (['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0)
            throw new Error(`tokenBinding.status 的值意外："${tokenBinding.status}"`);
    }

    const attestationObject = toBuffer(attestationResponse.attestationObject),
        decodedAttestationObject = decodeAttestationObject(attestationObject), fmt = decodedAttestationObject.get('fmt'),
        authData = decodedAttestationObject.get('authData'), attStmt = decodedAttestationObject.get('attStmt'),
        parsedAuthData = parseAuthenticatorData(authData),
        { aaguid, rpIdHash, flags, credentialID, counter, credentialPublicKey, extensionsData } = parsedAuthData;

    // 确保响应的 RP ID 是我们的
    let matchedRPID;
    if (expectedRPID) {
        let expectedRPIDs = [];
        if (typeof expectedRPID === 'string') expectedRPIDs = [expectedRPID];
        else expectedRPIDs = expectedRPID;
        matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);
    }

    // 确保有人物理存在
    if (requireUserPresence && !flags.up) throw new Error('要求用户存在,但找不到用户');
    // 如果指定了用户验证则强制执行
    if (requireUserVerification && !flags.uv) throw new Error('要求用户验证,但无法强制执行');
    if (!credentialID) throw new Error('身份验证器未提供凭证 ID');
    if (!credentialPublicKey) throw new Error('身份验证器未提供公钥');
    if (!aaguid) throw new Error('注册过程中未提供 AAGUID');

    const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey), alg = decodedPublicKey.get(COSEKEYS.alg);
    if (typeof alg !== 'number') throw new Error('凭证公钥缺少数值类型的 alg');

    // 确保密钥算法是我们注册选项中指定的算法之一
    if (!supportedAlgorithmIDs.includes(alg)) {
        const supported = supportedAlgorithmIDs.join(', ');
        throw new Error(`意外的公钥 alg "${alg}",期望为以下之一："${supported}"`);
    }

    const clientDataHash = await toHash(toBuffer(attestationResponse.clientDataJSON)),
        rootCertificates = SettingsService.getRootCertificates({ identifier: fmt }),
        // 准备传递给相关验证方法的参数
        verifierOpts = {
            aaguid, attStmt, authData, clientDataHash, credentialID, credentialPublicKey,
            rootCertificates, rpIdHash, attestationSafetyNetEnforceCTSCheck,
        };

    /**
     * 仅在 attestation = 'direct' 时可执行验证
     */
    let verified = false;
    if (fmt === 'fido-u2f') verified = await verifyAttestationFIDOU2F(verifierOpts);
    else if (fmt === 'packed') verified = await verifyAttestationPacked(verifierOpts);
    else if (fmt === 'android-safetynet') verified = await verifyAttestationAndroidSafetyNet(verifierOpts);
    else if (fmt === 'android-key') verified = await verifyAttestationAndroidKey(verifierOpts);
    else if (fmt === 'tpm') verified = await verifyAttestationTPM(verifierOpts);
    else if (fmt === 'apple') verified = await verifyAttestationApple(verifierOpts);
    else if (fmt === 'none') {
        if (attStmt.size > 0) throw new Error('None 证明存在意外的证明语句');
        verified = true; // 这是较弱的证明方式,没有其他需要检查的内容
    }
    else throw new Error(`不支持的证明格式：${fmt}`);
    if (!verified) return { verified: false };

    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);
    return {
        verified: true,
        registrationInfo: {
            fmt,
            aaguid: convertAAGUIDToString(aaguid),
            credentialType,
            credential: {
                id: fromBuffer(credentialID), publicKey: credentialPublicKey,
                counter, transports: response.response.transports,
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

export { verifyRegistrationResponse };