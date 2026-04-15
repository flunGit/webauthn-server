import {
    isoBase64URL, isoUint8Array, decodeClientDataJSON, toHash, verifySignature, parseAuthenticatorData,
    parseBackupFlags, matchExpectedRPID
} from '../helpers/index.js';

const { isBase64URL, toBuffer } = isoBase64URL;
/**
 * 验证用户是否合法完成了认证流程
 *
 * **选项说明：**
 *
 * @param response - 由 **flun-webauthn-browser** 的 `startAuthentication()` 返回的响应
 * @param expectedChallenge - Base64URL 编码的 `options.challenge`,即 `generateAuthenticationOptions()` 返回的值
 * @param expectedOrigin - 认证应发生的网站 URL（或 URL 数组）
 * @param expectedRPID - 认证选项中指定的 RP ID（或 ID 数组）
 * @param credential - 与认证响应中的 `id` 对应的内部 {@link WebAuthnCredential}
 * @param expectedType **（可选）** - 期望的响应类型（'webauthn.get'）
 * @param requireUserVerification **（可选）** - 强制要求身份验证器进行用户验证（通过 PIN、指纹等）;默认为 `true`
 * @param advancedFIDOConfig **（可选）** - 用于满足更严格的 FIDO 依赖方（RP）功能要求的选项
 * @param advancedFIDOConfig.userVerification **（可选）** - 启用替代规则来评估身份验证器数据中的用户存在（UP）
 * 和用户验证（UV）标志：除非此值为 `"required"`,否则 UV（和 UP）标志为可选
 */
async function verifyAuthenticationResponse(options) {
    const {
        response, expectedChallenge, expectedOrigin, expectedRPID, expectedType,
        credential, requireUserVerification = true, advancedFIDOConfig,
    } = options, { id, rawId, type: credentialType, response: assertionResponse } = response;

    if (!id) throw new Error('缺少凭证 ID');
    if (id !== rawId) throw new Error('凭证 ID 不是 base64url 编码');
    if (credentialType !== 'public-key') throw new Error(`意外的凭证类型 ${credentialType},期望 "public-key"`);
    if (!response) throw new Error('凭证缺少响应');
    if (typeof assertionResponse?.clientDataJSON !== 'string') throw new Error('凭证响应中的 clientDataJSON 不是字符串');

    const clientDataJSON = decodeClientDataJSON(assertionResponse.clientDataJSON),
        { type, origin, challenge, tokenBinding } = clientDataJSON;

    // 确保我们正在处理一次认证
    if (Array.isArray(expectedType)) {
        if (!expectedType.includes(type)) {
            const joinedExpectedType = expectedType.join(', ');
            throw new Error(`意外的认证响应类型 "${type}",期望以下之一：${joinedExpectedType}`);
        }
    } else if (expectedType) {
        if (type !== expectedType) throw new Error(`意外的认证响应类型 "${type}",期望 "${expectedType}"`);
    }
    else if (type !== 'webauthn.get') throw new Error(`意外的认证响应类型：${type}`);

    // 确保设备提供了我们给出的 challenge
    if (typeof expectedChallenge === 'function') {
        if (!(await expectedChallenge(challenge)))
            throw new Error(`自定义 challenge 验证器对注册响应中的 challenge "${challenge}" 返回了 false`);
    }
    else if (challenge !== expectedChallenge)
        throw new Error(`意外的认证响应 challenge "${challenge}"，期望 "${expectedChallenge}"`);

    // 检查 origin 是否为我们的站点
    if (Array.isArray(expectedOrigin)) {
        if (!expectedOrigin.includes(origin)) {
            const joinedExpectedOrigin = expectedOrigin.join(', ');
            throw new Error(`意外的认证响应来源 "${origin}",期望以下之一：${joinedExpectedOrigin}`);
        }
    }
    else if (origin !== expectedOrigin) throw new Error(`意外的认证响应来源 "${origin}",期望 "${expectedOrigin}"`);

    if (!isBase64URL(assertionResponse.authenticatorData))
        throw new Error('凭证响应中的 authenticatorData 不是 base64url 字符串');
    if (!isBase64URL(assertionResponse.signature))
        throw new Error('凭证响应中的 signature 不是 base64url 字符串');
    if (assertionResponse.userHandle && typeof assertionResponse.userHandle !== 'string')
        throw new Error('凭证响应中的 userHandle 不是字符串');
    if (tokenBinding) {
        if (typeof tokenBinding !== 'object') throw new Error('ClientDataJSON 中的 tokenBinding 不是对象');
        if (['present', 'supported', 'notSupported'].indexOf(tokenBinding.status) < 0)
            throw new Error(`意外的 tokenBinding 状态 ${tokenBinding.status}`);
    }

    const authDataBuffer = toBuffer(assertionResponse.authenticatorData),
        parsedAuthData = parseAuthenticatorData(authDataBuffer), { rpIdHash, flags, counter, extensionsData } = parsedAuthData;

    // 确保响应中的 RP ID 是我们的
    let expectedRPIDs = [];
    if (typeof expectedRPID === 'string') expectedRPIDs = [expectedRPID];
    else expectedRPIDs = expectedRPID;

    const matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);
    if (advancedFIDOConfig !== undefined) {
        const { userVerification: fidoUserVerification } = advancedFIDOConfig;

        /**
         * 使用 FIDO 一致性测试定义的规则来验证 UP 和 UV 标志
         */
        if (fidoUserVerification === 'required') {
            // 要求 `flags.uv` 为 true（这意味着 `flags.up` 也为 true）
            if (!flags.uv) throw new Error('需要用户验证,但用户无法被验证');
        } else if (fidoUserVerification === 'preferred' || fidoUserVerification === 'discouraged'); // 忽略 `flags.uv`
    } else {
        /**
         * 使用 WebAuthn 规范定义的规则来验证 UP 和 UV 标志
         */
        // WebAuthn 只要求用户存在标志为 true
        if (!flags.up) throw new Error('认证过程中用户未出现');

        // 如果要求用户验证,则强制执行
        if (requireUserVerification && !flags.uv) throw new Error('需要用户验证,但用户无法被验证');
    }

    const clientDataHash = await toHash(toBuffer(assertionResponse.clientDataJSON)),
        signatureBase = isoUint8Array.concat([authDataBuffer, clientDataHash]),
        signature = toBuffer(assertionResponse.signature);

    // 如果数据库中的 counter 大于或等于 dataStruct 中的 counter,则报错;
    // 这与身份验证器维护其被此客户端使用的次数有关;如果发生这种情况,
    // 说明有人未经由此网站就增加了设备上的计数器;
    if ((counter > 0 || credential.counter > 0) && counter <= credential.counter)
        throw new Error(`响应中的 counter 值 ${counter} 低于期望值 ${credential.counter}`);

    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags),
        toReturn = {
            verified: await verifySignature({
                signature, data: signatureBase, credentialPublicKey: credential.publicKey,
            }),
            authenticationInfo: {
                rpID: matchedRPID, newCounter: counter, credentialID: credential.id, userVerified: flags.uv, credentialDeviceType,
                credentialBackedUp, authenticatorExtensionResults: extensionsData, origin: clientDataJSON.origin
            },
        };

    return toReturn;
}

export { verifyAuthenticationResponse };