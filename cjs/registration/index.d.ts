import type {
    AuthenticationExtensionsClientInputs, AuthenticatorSelectionCriteria, AuthenticatorTransportFuture,
    Base64URLString, COSEAlgorithmIdentifier, PublicKeyCredentialCreationOptionsJSON, Uint8Array_,
    CredentialDeviceType, RegistrationResponseJSON, WebAuthnCredential
} from '../types/index.js';
import type { AttestationFormat, AttestationStatement, AuthenticationExtensionsAuthenticatorOutputs } from '../helpers/index.js';

// ================================= generateRegistrationOptions.js =================================
export type GenerateRegistrationOptionsOpts = Parameters<typeof generateRegistrationOptions>[0];

/**
 * 支持的加密算法标识符
 * 参见 https://w3c.github.io/webauthn/#sctn-alg-identifier
 * 以及 https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export declare const supportedCOSEAlgorithmIdentifiers: COSEAlgorithmIdentifier[];

/**
 * 生成用于身份验证器注册的参数,该参数可直接传递给 `navigator.credentials.create(...)`
 *
 * **选项说明：**
 *
 * @param rpName - 用户可见的、友好的网站/服务名称
 * @param rpID - 有效的域名（`https://` 之后的部分）
 * @param userName - 用户在当前网站的特定用户名（例如邮箱等）
 * @param userID **（可选）** - 用户在当前网站的唯一标识符,默认会生成一个随机标识符
 * @param challenge **（可选）** - 随机值，身份验证器需要对其签名并返回,默认会生成一个随机值
 * @param userDisplayName **（可选）** - 用户的真实姓名,默认为 `""`
 * @param timeout **（可选）** - 用户完成证明（attestation）所允许的最长时间（毫秒）;默认为 `60000`
 * @param attestationType **（可选）** - 具体的证明声明类型,默认为 `"none"`
 * @param excludeCredentials **（可选）** - 用户已注册的身份验证器列表,防止同一凭证被重复注册;默认为 `[]`
 * @param authenticatorSelection **（可选）** - 用于限制可使用的身份验证器类型的高级条件,
 * 默认为 `{ residentKey: 'preferred', userVerification: 'preferred' }`
 * @param extensions **（可选）** - 身份验证器或浏览器在证明过程中应使用的附加插件/扩展
 * @param supportedAlgorithmIDs **（可选）** - 当前依赖方（RP）支持的用于证明的 COSE 算法标识符数组,
 *  参见 https://www.iana.org/assignments/cose/cose.xhtml#algorithms;默认为 `[-8, -7, -257]`
 * @param preferredAuthenticatorType **（可选）** - 建议浏览器提示用户注册特定类型的身份验证器
 */
export declare function generateRegistrationOptions(options: {
    rpName: string, rpID: string, userName: string;
    userID?: Uint8Array_;
    challenge?: string | Uint8Array_;
    userDisplayName?: string;
    timeout?: number;
    attestationType?: 'direct' | 'enterprise' | 'none';
    excludeCredentials?: {
        id: Base64URLString, transports?: AuthenticatorTransportFuture[];
    }[];
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    extensions?: AuthenticationExtensionsClientInputs;
    supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
    preferredAuthenticatorType?: 'securityKey' | 'localDevice' | 'remoteDevice';
}): Promise<PublicKeyCredentialCreationOptionsJSON>;

// ================================= verifyRegistrationResponse.js =================================
/**
 * 调用 `verifyRegistrationResponse()` 时的可配置选项
 */
export type VerifyRegistrationResponseOpts = Parameters<typeof verifyRegistrationResponse>[0];

/**
 * 验证用户是否合法地完成了注册流程
 *
 * **选项说明：**
 *
 * @param response - 由 **flun-webauthn-browser** 的 `startAuthentication()` 返回的响应
 * @param expectedChallenge - 由 `generateRegistrationOptions()` 返回的 `options.challenge` 的 base64url 编码值
 * @param expectedOrigin - 注册应当发生的网站 URL（或 URL 数组）
 * @param expectedRPID - 注册选项中指定的 RP ID（或 ID 数组）
 * @param expectedType **（可选）** - 期望的响应类型（'webauthn.create'）
 * @param requireUserPresence **（可选）** - 强制要求身份验证器验证用户存在（或在自动注册时跳过）,默认为 `true`
 * @param requireUserVerification **（可选）** - 强制要求身份验证器验证用户（通过 PIN、指纹等）,默认为 `true`
 * @param supportedAlgorithmIDs **（可选）** - 本 RP 支持的用于认证的 COSE 算法标识符数值数组,
 * 参见 https://www.iana.org/assignments/cose/cose.xhtml#algorithms,默认为所有支持的算法 ID
 * @param attestationSafetyNetEnforceCTSCheck **（可选）** - 若使用 SafetyNet 认证,要求 Android 设备的系统完整性未被篡改,默认为 `true`
 */
export declare function verifyRegistrationResponse(options: {
    response: RegistrationResponseJSON;
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>);
    expectedOrigin: string | string[], expectedRPID?: string | string[], expectedType?: string | string[];
    requireUserPresence?: boolean, requireUserVerification?: boolean, attestationSafetyNetEnforceCTSCheck?: boolean;
    supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
}): Promise<VerifiedRegistrationResponse>;

/**
 * 注册验证结果
 *
 * @param verified - 断言响应是否验证通过
 * @param registrationInfo.fmt - 认证类型
 * @param registrationInfo.counter - 身份验证器报告已使用的次数;
 * **应保存在数据库中以供后续参考,有助于防范重放攻击！**
 * @param registrationInfo.aaguid - 身份验证器的认证 GUID，指示身份验证器的类型
 * @param registrationInfo.credentialPublicKey - 凭证的公钥
 * @param registrationInfo.credentialID - 上述公钥对应的凭证 ID
 * @param registrationInfo.credentialType - 浏览器返回的凭证类型
 * @param registrationInfo.userVerified - 认证过程中用户是否被唯一标识
 * @param registrationInfo.attestationObject - 身份验证器返回的原始 `response.attestationObject` 缓冲区
 * @param registrationInfo.credentialDeviceType - 该凭证是单设备凭证还是多设备凭证;
 * **应保存在数据库中以供后续参考！**
 * @param registrationInfo.credentialBackedUp - 多设备凭证是否已被备份,对于单设备凭证始终为 `false`;
 * **应保存在数据库中以供后续参考！**
 * @param registrationInfo.origin - 注册发生的网站源（origin）
 * @param registrationInfo?.rpID - 注册发生的 RP ID（如果在注册选项中指定了一个或多个）
 * @param registrationInfo?.authenticatorExtensionResults - 浏览器返回的身份验证器扩展结果
 */
export type VerifiedRegistrationResponse = {
    verified: false, registrationInfo?: never;
} | {
    verified: true;
    registrationInfo: {
        fmt: AttestationFormat;
        aaguid: string;
        credential: WebAuthnCredential;
        credentialType: 'public-key';
        attestationObject: Uint8Array_;
        credentialDeviceType: CredentialDeviceType;
        userVerified: boolean, credentialBackedUp: boolean;
        origin: string, rpID?: string;
        authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
    };
};

/**
 * 传递给所有认证格式验证器的值,各验证器可自行决定如何使用
 */
export type AttestationFormatVerifierOpts = {
    attStmt: AttestationStatement;
    aaguid: Uint8Array_, authData: Uint8Array_, clientDataHash: Uint8Array_, credentialID: Uint8Array_,
    credentialPublicKey: Uint8Array_, rpIdHash: Uint8Array_;
    rootCertificates: string[];
    verifyTimestampMS?: boolean, attestationSafetyNetEnforceCTSCheck?: boolean;
};