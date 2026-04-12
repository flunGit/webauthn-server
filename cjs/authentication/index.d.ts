import type {
    AuthenticationExtensionsClientInputs, AuthenticatorTransportFuture, Base64URLString, AuthenticationResponseJSON,
    PublicKeyCredentialRequestOptionsJSON, CredentialDeviceType, UserVerificationRequirement, WebAuthnCredential,
    Uint8Array_
} from '../types/index.js';

import type { AuthenticationExtensionsAuthenticatorOutputs } from '../helpers/index.js';

// ================================= generateAuthenticationOptions.js =================================
export type GenerateAuthenticationOptionsOpts = Parameters<typeof generateAuthenticationOptions>[0];
/**
 * 生成用于身份验证器认证的参数,该参数可直接传递给 `navigator.credentials.get(...)`
 *
 * **选项说明：**
 *
 * @param rpID - 有效的域名（`https://` 之后的部分）
 * @param allowCredentials **（可选）** - 用户之前注册过的身份验证器列表（如有）;如果未提供,客户端将询问用户选择要使用的凭证
 * @param challenge **（可选）** - 随机值,身份验证器需要对其签名并返回以完成用户认证;默认会生成一个随机值
 * @param timeout **（可选）** - 用户完成认证所允许的最长时间（毫秒）。默认为 `60000`
 * @param userVerification **（可选）** - 在作为双因素认证流程的一部分进行断言时设置为 `'discouraged'`，否则根据需要设置为 `'preferred'` 或 `'required'`。默认为 `"preferred"`
 * @param extensions **（可选）** - 身份验证器或浏览器在认证过程中应使用的附加插件/扩展
 */
export declare function generateAuthenticationOptions(options: {
    rpID: string;
    allowCredentials?: {
        id: Base64URLString;
        transports?: AuthenticatorTransportFuture[];
    }[];
    challenge?: string | Uint8Array_;
    timeout?: number;
    userVerification?: 'required' | 'preferred' | 'discouraged';
    extensions?: AuthenticationExtensionsClientInputs;
}): Promise<PublicKeyCredentialRequestOptionsJSON>;

// ================================= verifyAuthenticationResponse.js =================================
/**
 * 调用 `verifyAuthenticationResponse()` 时的可配置选项
 */
export type VerifyAuthenticationResponseOpts = Parameters<typeof verifyAuthenticationResponse>[0];

/**
 * 验证用户是否合法完成了认证流程
 *
 * **选项说明：**
 *
 * @param response - 由 **flun-webauthn-browser** 的 `startAuthentication()` 返回的响应
 * @param expectedChallenge - Base64URL 编码的 `options.challenge`，即 `generateAuthenticationOptions()` 返回的值
 * @param expectedOrigin - 认证应发生的网站 URL（或 URL 数组）
 * @param expectedRPID - 认证选项中指定的 RP ID（或 ID 数组）
 * @param credential - 与认证响应中的 `id` 对应的内部 {@link WebAuthnCredential}
 * @param expectedType **（可选）** - 期望的响应类型（'webauthn.get'）
 * @param requireUserVerification **（可选）** - 强制要求身份验证器进行用户验证（通过 PIN、指纹等）;默认为 `true`
 * @param advancedFIDOConfig **（可选）** - 用于满足更严格的 FIDO 依赖方（RP）功能要求的选项
 * @param advancedFIDOConfig.userVerification **（可选）** - 启用替代规则来评估身份验证器数据中的用户存在（UP）
 *   和用户验证（UV）标志：除非此值为 `"required"`，否则 UV（和 UP）标志为可选
 */
export declare function verifyAuthenticationResponse(options: {
    response: AuthenticationResponseJSON,
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>),
    expectedOrigin: string | string[], expectedRPID: string | string[],
    credential: WebAuthnCredential, expectedType?: string | string[];
    requireUserVerification?: boolean,
    advancedFIDOConfig?: { userVerification?: UserVerificationRequirement, },
}): Promise<VerifiedAuthenticationResponse>;

/**
 * 认证验证结果
 *
 * @param verified - 认证响应是否验证成功
 * @param authenticationInfo.credentialID - 认证过程中使用的身份验证器的 ID;
 * 可用于识别数据库中的哪个身份验证器条目需要将其 `counter` 更新为下面的值
 * @param authenticationInfo.newCounter - 上述身份验证器报告其已被使用的次数;
 * **应保存在数据库中供后续参考,以帮助防止重放攻击！**
 * @param authenticationInfo.credentialDeviceType - 该凭证是单设备凭证还是多设备凭证;
 * **应保存在数据库中供后续参考！**
 * @param authenticationInfo.credentialBackedUp - 多设备凭证是否已被备份;对于单设备凭证始终为 `false`;
 * **应保存在数据库中供后续参考！**
 * @param authenticationInfo.origin - 认证发生时的网站来源
 * @param authenticationInfo.rpID - 认证发生时的 RP ID
 * @param authenticationInfo?.authenticatorExtensionResults - 浏览器返回的身份验证器扩展结果
 */
export type VerifiedAuthenticationResponse = {
    verified: boolean;
    authenticationInfo: {
        credentialID: Base64URLString; newCounter: number; userVerified: boolean;
        credentialDeviceType: CredentialDeviceType;
        credentialBackedUp: boolean; origin: string; rpID: string;
        authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
    };
};
