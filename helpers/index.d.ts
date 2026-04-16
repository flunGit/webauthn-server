export { isoBase64URL, isoCBOR, isoCrypto, isoUint8Array } from './iso/index.js';
export * from '../metadata/index.js';
import type { Base64URLString, Uint8Array_, CredentialDeviceType } from '../types/index.js';
import { Certificate, Extensions } from '@peculiar/asn1-x509';
import { type X509Certificate } from '@peculiar/x509';

// ================================= convertAAGUIDToString.js =================================
/**
 * ```js
 * // 文件导出内容:
 * convertAAGUIDToString(); // 将 authData 中的 aaguid 缓冲区转换为 UUID 字符串
 * ```
 * ---
 * - 查看定义:@see {@link convertAAGUIDToString}
 */
declare module './convertAAGUIDToString.js' {
    /**
     * 将 authData 中的 aaguid 缓冲区转换为 UUID 字符串
     */
    export function convertAAGUIDToString(aaguid: Uint8Array_): string;
}

// ================================= convertCertBufferToPEM.js =================================
/**
 * ```js
 * // 文件导出内容:
 * convertCertBufferToPEM(); // 将缓冲区转换为 OpenSSL 兼容的 PEM 文本格式
 * ```
 * ---
 * - 查看定义:@see {@link convertCertBufferToPEM}
 */
declare module './convertCertBufferToPEM.js' {
    /**
     * 将缓冲区转换为 OpenSSL 兼容的 PEM 文本格式;
     */
    export function convertCertBufferToPEM(certBuffer: Uint8Array_ | Base64URLString): string;
}

// ================================= convertCOSEtoPKCS.js =================================
/**
 * ```js
 * // 文件导出内容:
 * convertCOSEtoPKCS(); // 接收 COSE 编码的公钥，并将其转换为 PKCS 密钥
 * ```
 * ---
 * - 查看定义:@see {@link convertCOSEtoPKCS}
 */
declare module './convertCOSEtoPKCS.js' {
    /**
     * 接收 COSE 编码的公钥,并将其转换为 PKCS 密钥
     */
    export function convertCOSEtoPKCS(cosePublicKey: Uint8Array_): Uint8Array_;
}

// ================================= convertPEMToBytes.js =================================
/**
 * ```js
 * // 文件导出内容:
 * convertPEMToBytes(); // 将 PEM 格式的证书转换为字节数组
 * ```
 * ---
 * - 查看定义:@see {@link convertPEMToBytes}
 */
declare module './convertPEMToBytes.js' {
    /**
     * 将 PEM 格式的证书转换为字节数组
     */
    export function convertPEMToBytes(pem: string): Uint8Array_;
}

// ================================= convertX509PublicKeyToCOSE.js =================================
/**
 * ```js
 * // 文件导出内容:
 * convertX509PublicKeyToCOSE(); // 从 X.509 证书（DER 格式）中提取公钥，并将其转换为 COSE 公钥结构
 * ```
 * ---
 * - 查看定义:@see {@link convertX509PublicKeyToCOSE}
 */
declare module './convertX509PublicKeyToCOSE.js' {
    /**
     * 从 X.509 证书（DER 格式）中提取公钥，并将其转换为 COSE 公钥结构
     *
     * @param x509Certificate - DER 编码的 X.509 证书缓冲区
     * @returns 解析出的 COSE 公钥 Map 对象，可根据密钥类型（OKP/EC2/RSA）使用类型守卫进行细化
     * @throws 若证书格式无效或公钥类型不受支持，将抛出错误
     * - 查看定义:@see {@link https://datatracker.ietf.org/doc/html/rfc9052#name-cose-key-map|COSE Key Map Specification}
     */
    export function convertX509PublicKeyToCOSE(x509Certificate: Uint8Array_): COSEPublicKey;
}

// ================================= cose.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type COSEPublicKey, COSEPublicKeyOKP, COSEPublicKeyEC2, COSEPublicKeyRSA;
 *
 * // 枚举常量
 * enum COSEKEYS, COSEKTY, COSECRV, COSEALG;
 *
 * // 类型守卫函数
 * isCOSEPublicKeyOKP(), isCOSEPublicKeyEC2(), isCOSEPublicKeyRSA();
 * isCOSEKty(), isCOSECrv(), isCOSEAlg();
 * ```
 * ---
 * - 查看定义:@see {@link COSEPublicKey}、{@link COSEPublicKeyOKP}、{@link COSEPublicKeyEC2}、{@link COSEPublicKeyRSA}、
 * - {@link COSEKEYS}、{@link COSEKTY}、{@link COSECRV}、{@link COSEALG}、{@link isCOSEPublicKeyOKP}、
 * - {@link isCOSEPublicKeyEC2}、{@link isCOSEPublicKeyRSA}、{@link isCOSEKty}、{@link isCOSECrv}、{@link isCOSEAlg}
 *
 * 以下基本值用于区分下面更具体的 COSE 公钥类型;
 *
 * 这里使用 `Map` 是因为公钥使用了 CBOR 编码,而 CBOR 的 "Map" 类型在解码时会变成 JavaScript 的 `Map` 类型,
 * 而不是我们 JS 开发者更习惯的普通对象;
 *
 * 这些类型以一种非传统的方式表达了“这些 Map 应该包含下面这些离散的键列表”,但这样是可行的;
 */
declare module './cose.js' {
    /**
     * COSE 公钥通用值
     */
    export type COSEPublicKey = {
        get(key: COSEKEYS.kty): COSEKTY | undefined, get(key: COSEKEYS.alg): COSEALG | undefined;
        set(key: COSEKEYS.kty, value: COSEKTY): void, set(key: COSEKEYS.alg, value: COSEALG): void;
    };

    /**
     * 八字节密钥对公钥特有的值
     */
    export type COSEPublicKeyOKP = COSEPublicKey & {
        get(key: COSEKEYS.crv): number | undefined, get(key: COSEKEYS.x): Uint8Array_ | undefined;
        set(key: COSEKEYS.crv, value: number): void, set(key: COSEKEYS.x, value: Uint8Array_): void;
    };

    /**
     * 椭圆曲线加密公钥特有的值
     */
    export type COSEPublicKeyEC2 = COSEPublicKey & {
        get(key: COSEKEYS.crv): number | undefined;
        get(key: COSEKEYS.x): Uint8Array_ | undefined, get(key: COSEKEYS.y): Uint8Array_ | undefined;
        set(key: COSEKEYS.crv, value: number): void;
        set(key: COSEKEYS.x, value: Uint8Array_): void, set(key: COSEKEYS.y, value: Uint8Array_): void;
    };

    /**
     * RSA 公钥特有的值
     */
    export type COSEPublicKeyRSA = COSEPublicKey & {
        get(key: COSEKEYS.n): Uint8Array_ | undefined, get(key: COSEKEYS.e): Uint8Array_ | undefined;
        set(key: COSEKEYS.n, value: Uint8Array_): void, set(key: COSEKEYS.e, value: Uint8Array_): void;
    };

    /**
     * 类型守卫：判断一个 COSE 公钥是否为 OKP 密钥对
     */
    export function isCOSEPublicKeyOKP(cosePublicKey: COSEPublicKey): cosePublicKey is COSEPublicKeyOKP;

    /**
     * 类型守卫：判断一个 COSE 公钥是否为 EC2 密钥对
     */
    export function isCOSEPublicKeyEC2(cosePublicKey: COSEPublicKey): cosePublicKey is COSEPublicKeyEC2;

    /**
     * 类型守卫：判断一个 COSE 公钥是否为 RSA 密钥对
     */
    export function isCOSEPublicKeyRSA(cosePublicKey: COSEPublicKey): cosePublicKey is COSEPublicKeyRSA;

    /**
     * COSE 键
     *
     * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
     * https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
     */
    export enum COSEKEYS { kty = 1, alg = 3, crv = -1, x = -2, y = -3, n = -1, e = -2 }

    /**
     * COSE 密钥类型
     *
     * https://www.iana.org/assignments/cose/cose.xhtml#key-type
     */
    export enum COSEKTY { OKP = 1, EC2 = 2, RSA = 3 }
    /**
     * 判断给定的数值是否为有效的 COSE 密钥类型（kty）
     *
     * @param kty - 待检测的密钥类型值（可能为 undefined）
     * @returns 类型谓词，若为有效的 COSEKTY 枚举值则返回 true，同时将类型收窄为 COSEKTY
     * - 查看定义:@see {@link https://www.iana.org/assignments/cose/cose.xhtml#key-type|COSE Key Type Registry}
     */
    export function isCOSEKty(kty: number | undefined): kty is COSEKTY;

    /**
     * COSE 椭圆曲线
     *
     * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
     */
    export enum COSECRV { P256 = 1, P384 = 2, P521 = 3, ED25519 = 6, SECP256K1 = 8 }
    /**
     * 判断给定的数值是否为有效的 COSE 椭圆曲线参数（crv）
     *
     * @param crv - 待检测的曲线参数值（可能为 undefined）
     * @returns 类型谓词，若为有效的 COSECRV 枚举值则返回 true，同时将类型收窄为 COSECRV
     * - 查看定义:@see {@link https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves|COSE Elliptic Curves Registry}
     */
    export function isCOSECrv(crv: number | undefined): crv is COSECRV;

    /**
     * COSE 算法
     *
     * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     */
    export enum COSEALG {
        ES256 = -7, EdDSA = -8, ES384 = -35, ES512 = -36, PS256 = -37, PS384 = -38, PS512 = -39, ES256K = -47,
        RS256 = -257, RS384 = -258, RS512 = -259, RS1 = -65535
    }
    /**
     * 判断给定的数值是否为有效的 COSE 算法标识（alg）
     *
     * @param alg - 待检测的算法标识值（可能为 undefined）
     * @returns 类型谓词，若为有效的 COSEALG 枚举值则返回 true，同时将类型收窄为 COSEALG
     * - 查看定义:@see {@link https://www.iana.org/assignments/cose/cose.xhtml#algorithms|COSE Algorithms Registry}
     */
    export function isCOSEAlg(alg: number | undefined): alg is COSEALG;
}

// ================================= decodeAttestationObject.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type AttestationFormat, AttestationObject, AttestationStatement;
 *
 * // 函数
 * decodeAttestationObject();
 * ```
 * ---
 * - 查看定义:@see {@link decodeAttestationObject}、{@link AttestationFormat}、{@link AttestationObject}、{@link AttestationStatement}
 */
declare module './decodeAttestationObject.js' {
    /**
     * 将 AttestationObject 缓冲区转换为对应的对象
     *
     * @param attestationObject Attestation Object 缓冲区
     */
    export function decodeAttestationObject(attestationObject: Uint8Array_): AttestationObject;
    export type AttestationFormat = | 'fido-u2f' | 'packed' | 'android-safetynet' | 'android-key' | 'tpm' | 'apple' | 'none';
    export type AttestationObject = {
        get(key: 'fmt'): AttestationFormat, get(key: 'attStmt'): AttestationStatement, get(key: 'authData'): Uint8Array_;
    };

    /**
     * `AttestationStatement` 是一个 `Map` 实例，但以下键限定了其中可能存在的值范围。
     */
    export type AttestationStatement = {
        get(key: 'sig'): Uint8Array_ | undefined, get(key: 'x5c'): Uint8Array_[] | undefined;
        get(key: 'response'): Uint8Array_ | undefined, get(key: 'certInfo'): Uint8Array_ | undefined;
        get(key: 'pubArea'): Uint8Array_ | undefined;
        get(key: 'ver'): string | undefined;
        get(key: 'alg'): number | undefined;
        readonly size: number;
    };

    /**
     * 用于在测试时模拟返回值
     * @ignore 不要在文档输出中包含此项
     */
    export const _decodeAttestationObjectInternals: {
        stubThis: (value: AttestationObject) => AttestationObject;
    };
}

// ================================= decodeAuthenticatorExtensions.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type AuthenticationExtensionsAuthenticatorOutputs;
 *
 * // 函数
 * decodeAuthenticatorExtensions();
 * ```
 * ---
 * - 查看定义:@see {@link decodeAuthenticatorExtensions}、{@link AuthenticationExtensionsAuthenticatorOutputs}
 */
declare module './decodeAuthenticatorExtensions.js' {
    /**
     * 将身份验证器扩展数据缓冲区转换为相应的对象
     *
     * @param extensionData 身份验证器扩展数据缓冲区
     */
    export function decodeAuthenticatorExtensions(extensionData: Uint8Array_)
        : AuthenticationExtensionsAuthenticatorOutputs | undefined;

    /**
     * 尝试支持 WebAuthn 中可能未知的身份验证器扩展
     */
    export type AuthenticationExtensionsAuthenticatorOutputs = unknown;
}

// ================================= decodeClientDataJSON.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type ClientDataJSON;
 *
 * // 函数
 * decodeClientDataJSON();
 * ```
 * ---
 * - 查看定义:@see {@link decodeClientDataJSON}、{@link ClientDataJSON}
 */
declare module './decodeClientDataJSON.js' {
    /**
     * 将身份验证器的 base64url 编码的 clientDataJSON 解码为 JSON
     */
    export function decodeClientDataJSON(data: Base64URLString): ClientDataJSON;

    export type ClientDataJSON = {
        type: string, challenge: string, origin: string;
        crossOrigin?: boolean;
        tokenBinding?: { id?: string; status: 'present' | 'supported' | 'not-supported' };
    };

    /**
     * 便于在测试时模拟（stub）返回值
     * @ignore 不要将此内容包含在文档输出中
     */
    export const _decodeClientDataJSONInternals: {
        stubThis: (value: ClientDataJSON) => ClientDataJSON;
    };
}

// ================================= decodeCredentialPublicKey.js =================================
/**
 * ```js
 * // 文件导出内容:
 * decodeCredentialPublicKey(); // 将 WebAuthn 凭证公钥（CBOR 编码的 COSE 公钥）解码为 COSEPublicKey Map 对象
 * ```
 * ---
 * - 查看定义:@see {@link decodeCredentialPublicKey}
 */
declare module './decodeCredentialPublicKey.js' {
    /**
     * 将 WebAuthn 凭证公钥（CBOR 编码的 COSE 公钥）解码为 COSEPublicKey Map 对象
     *
     * @param publicKey - 来自 authenticatorData 的凭证公钥缓冲区（CBOR 编码的 COSE_Key）
     * @returns 解码后的 COSE 公钥 Map，可通过类型守卫（isCOSEPublicKeyOKP / EC2 / RSA）进一步细化类型
     * @throws 如果输入不是有效的 CBOR 结构或不包含预期的 COSE 密钥参数，将抛出错误
     * - 查看定义:@see {@link https://www.w3.org/TR/webauthn-2/#sctn-public-key-easy|WebAuthn Credential Public Key}
     * - 查看定义:@see {@link https://datatracker.ietf.org/doc/html/rfc9052#name-cose-key-map|COSE Key Map Specification}
     */
    export function decodeCredentialPublicKey(publicKey: Uint8Array_): COSEPublicKey;

    /**
     * 使得在测试期间可以模拟（stub）返回值
     * @ignore 不要在文档输出中包含此项
     */
    export const _decodeCredentialPublicKeyInternals: {
        stubThis: (value: COSEPublicKey) => COSEPublicKey;
    };
}

// ================================= fetch.js =================================
/**
 * ```js
 * // 文件导出内容:
 * fetch(); // 一个用于通过标准 fetch 请求数据的简单方法,可在多种运行时环境中工作
 * ```
 * ---
 * - 查看定义:@see {@link fetch}
 */
declare module './fetch.js' {
    /**
     * 一个用于通过标准 `fetch` 请求数据的简单方法,可在多种运行时环境中工作;
     */
    export function fetch(url: string): Promise<Response>;

    /**
     * 用于在测试期间模拟返回值的内部实现
     * @ignore 不要将此内容包含在文档输出中
     */
    export const _fetchInternals: {
        stubThis: (url: string) => Promise<Response>;
    };
}

// ================================= generateChallenge.js =================================
/**
 * ```js
 * // 文件导出内容:
 * generateChallenge(); // 生成一个合适的随机值,用作证明（attestation）或断言（assertion）的挑战值（challenge）
 * ```
 * ---
 * - 查看定义:@see {@link generateChallenge}
 */
declare module './generateChallenge.js' {
    /**
     * 生成一个合适的随机值,用作证明（attestation）或断言（assertion）的挑战值（challenge）
     */
    export function generateChallenge(): Promise<Uint8Array_>;

    /**
     * 便于在测试时对返回值进行模拟（stub）
     * @ignore 不要在文档输出中包含此项
     */
    export const _generateChallengeInternals: {
        stubThis: (value: Uint8Array_) => Uint8Array;
    };
}

// ================================= generateUserID.js =================================
/**
 * ```js
 * // 文件导出内容:
 * generateUserID(); // 生成一个适合作为用户 ID 的随机值
 * ```
 * ---
 * - 查看定义:@see {@link generateUserID}
 */
declare module './generateUserID.js' {
    /**
     * 生成一个适合作为用户 ID 的随机值
     */
    export function generateUserID(): Promise<Uint8Array_>;

    /**
     * 使测试期间能够对返回值进行桩（stub）替换
     * @ignore 不要在文档输出中包含此项
     */
    export const _generateUserIDInternals: {
        stubThis: (value: Uint8Array_) => Uint8Array;
    };
}

// ================================= getCertificateInfo.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type CertificateInfo, Issuer, Subject;
 *
 * // 函数
 * getCertificateInfo();
 * ```
 * ---
 * - 查看定义:@see {@link getCertificateInfo}、{@link CertificateInfo}、{@link Issuer}、{@link Subject}
 */
declare module './getCertificateInfo.js' {
    export type CertificateInfo = {
        issuer: Issuer;
        subject: Subject;
        version: number;
        basicConstraintsCA: boolean;
        notBefore: Date, notAfter: Date;
        parsedCertificate: Certificate;
    };

    type Issuer = { C?: string, O?: string, OU?: string, CN?: string, combined: string };
    type Subject = { C?: string, O?: string, OU?: string, CN?: string, combined: string };

    /**
     * 提取 PEM 证书信息
     *
     * @param pemCertificate - 调用 `convertASN1toPEM(x5c[0])` 后得到的结果
     */
    export function getCertificateInfo(leafCertBuffer: Uint8Array_): CertificateInfo;
}

// ================================= isCertRevoked.js =================================
/**
 * ```js
 * // 文件导出内容:
 * isCertRevoked(); // 从证书中获取证书吊销列表（CRL）,并将其中的序列号与 CRL 内已吊销证书的序列号进行比对
 * ```
 * ---
 * - 查看定义:@see {@link isCertRevoked}
 */
declare module './isCertRevoked.js' {
    /**
     * 从证书中获取证书吊销列表（CRL）,并将其中的序列号与 CRL 内已吊销证书的序列号进行比对的方法;
     *
     * CRL 证书结构参考自 https://tools.ietf.org/html/rfc5280#page-117
     */
    export function isCertRevoked(cert: X509Certificate): Promise<boolean>;
}

// ================================= logging.js =================================
/**
 * ```js
 * // 文件导出内容:
 * getLogger(); // 生成一个 debug 日志记录器的实例,该实例基于 "flunWebauthn" 扩展
 * ```
 * ---
 * - 查看定义:@see {@link getLogger}
 */
declare module './logging.js' {
    /**
     * 生成一个 `debug` 日志记录器的实例,该实例基于 "flunWebauthn" 扩展,以保证命名一致性;
     *
     * 有关如何在使用 flun-webauthn-server 时控制日志输出的信息,请参阅 https://www.npmjs.com/package/debug
     *
     * 示例：
     *
     * ```
     * const log = getLogger('mds');
     * log('hello'); // flunWebauthn:mds hello +0ms
     * ```
     */
    export function getLogger(_name: string): (message: string, ..._rest: unknown[]) => void;
}

// ================================= mapX509SignatureAlgToCOSEAlg.js =================================
/**
 * ```js
 * // 文件导出内容:
 * mapX509SignatureAlgToCOSEAlg(); // 将 X.509 签名算法 OID 映射到 COSE 算法 ID
 * ```
 * ---
 * - 查看定义:@see {@link mapX509SignatureAlgToCOSEAlg}
 */
declare module './mapX509SignatureAlgToCOSEAlg.js' {
    /**
     * 将 X.509 签名算法 OID 映射到 COSE 算法 ID
     *
     * - EC2 OID：https://oidref.com/1.2.840.10045.4.3
     * - RSA OID：https://oidref.com/1.2.840.113549.1.1
     */
    export function mapX509SignatureAlgToCOSEAlg(signatureAlgorithm: string): COSEALG;
}

// ================================= matchExpectedRPID.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类
 * class UnexpectedRPIDHash;
 *
 * // 函数
 * matchExpectedRPID();
 * ```
 * ---
 * - 查看定义:@see {@link matchExpectedRPID}、{@link UnexpectedRPIDHash}
 */
declare module './matchExpectedRPID.js' {
    /**
     * 遍历每一个预期的 RP ID,尝试找到匹配项,返回与响应中的哈希值匹配的未哈希 RP ID;
     *
     * 如果未找到匹配项,则抛出 `UnexpectedRPIDHash` 错误;
     */
    export function matchExpectedRPID(rpIDHash: Uint8Array_, expectedRPIDs: string[]): Promise<string>;

    /**
     * 当响应中的 RP ID 哈希值与所有预期的 RP ID 均不匹配时抛出的错误;
     */
    export class UnexpectedRPIDHash extends Error { constructor(); }
}

// ================================= parseAuthenticatorData.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type ParsedAuthenticatorData;
 *
 * // 函数
 * parseAuthenticatorData();
 * ```
 * ---
 * - 查看定义:@see {@link parseAuthenticatorData}、{@link ParsedAuthenticatorData}
 */
declare module './parseAuthenticatorData.js' {
    /**
     * 解析 Attestation 中包含的 authData 缓冲区,使其变得可读
     */
    export function parseAuthenticatorData(authData: Uint8Array_): ParsedAuthenticatorData;

    export type ParsedAuthenticatorData = {
        rpIdHash: Uint8Array_, flagsBuf: Uint8Array_;
        flags: {
            up: boolean, uv: boolean, be: boolean, bs: boolean, at: boolean, ed: boolean;
            flagsInt: number;
        };
        counter: number;
        counterBuf: Uint8Array_, aaguid?: Uint8Array_;
        credentialID?: Uint8Array_, credentialPublicKey?: Uint8Array_;
        extensionsData?: AuthenticationExtensionsAuthenticatorOutputs;
        extensionsDataBuffer?: Uint8Array_;
    };

    /**
     * 便于在测试时对返回值进行打桩（stub）
     * @ignore 不要将此内容包含在文档输出中
     */
    export const _parseAuthenticatorDataInternals: {
        stubThis: (value: ParsedAuthenticatorData) => ParsedAuthenticatorData;
    };
}

// ================================= parseBackupFlags.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类
 * class InvalidBackupFlags;
 *
 * // 函数
 * parseBackupFlags();
 * ```
 * ---
 * - 查看定义:@see {@link parseBackupFlags}、{@link InvalidBackupFlags}
 */
declare module './parseBackupFlags.js' {
    /**
     * 解析身份验证器中的第 3 位和第 4 位,这些位表示：
     *
     * - 凭证是否可用于多台设备
     * - 凭证是否已备份
     *
     * 若配置无效将抛出 `Error`
     */
    export function parseBackupFlags({ be, bs }: { be: boolean, bs: boolean; })
        : { credentialDeviceType: CredentialDeviceType, credentialBackedUp: boolean };

    /**
     * 当解析备份标志（be/bs）时遇到无效组合（如单设备凭证却标记为已备份）抛出的错误;
     */
    export class InvalidBackupFlags extends Error { constructor(message: string) }
}

// ================================= toHash.js =================================
/**
 * ```js
 * // 文件导出内容:
 * toHash(); // 返回给定数据的哈希摘要,默认使用 SHA-256
 * ```
 * ---
 * - 查看定义:@see {@link toHash}
 */
declare module './toHash.js' {
    /**
     * 返回给定数据的哈希摘要,如果提供了算法参数,则使用指定的算法:默认使用 SHA-256;
     */
    export function toHash(data: Uint8Array_ | string, algorithm?: COSEALG): Promise<Uint8Array_>;
}

// ================================= validateCertificatePath.js =================================
/**
 * ```js
 * // 文件导出内容:
 * validateCertificatePath(); // 遍历 PEM 证书数组,确保形成有效的证书链
 * ```
 * ---
 * - 查看定义:@see {@link validateCertificatePath}
 */
declare module './validateCertificatePath.js' {
    /**
     * 遍历 PEM 证书数组,并确保它们形成有效的证书链
     * @param x5cCertsPEM - 通常是 `x5c.map(convertASN1toPEM)` 的结果
     * @param trustAnchorsPEM - PEM 格式的证书,认证声明中的 x5c 证书可回溯到这些受信任的根证书
     */
    export function validateCertificatePath(x5cCertsPEM: string[], trustAnchorsPEM?: string[]): Promise<boolean>;
}

// ================================= validateExtFIDOGenCEAAGUID.js =================================
/**
 * ```js
 * // 文件导出内容:
 * validateExtFIDOGenCEAAGUID(); // 查找 FIDO Gen CE AAGUID 证书扩展并比对 AAGUID
 * ```
 * ---
 * - 查看定义:@see {@link validateExtFIDOGenCEAAGUID}
 */
declare module './validateExtFIDOGenCEAAGUID.js' {
    /**
     * 查找 id-fido-gen-ce-aaguid 证书扩展,如果存在,则将其与证明语句中的 AAGUID 进行比对;
     */
    export function validateExtFIDOGenCEAAGUID(
        certExtensions: Extensions | undefined,
        aaguid: Uint8Array_
    ): boolean;
}

// ================================= verifySignature.js =================================
/**
 * ```js
 * // 文件导出内容:
 * verifySignature(); // 验证身份验证器的签名
 * ```
 * ---
 * - 查看定义:@see {@link verifySignature}
 */
declare module './verifySignature.js' {
    /**
     * 验证身份验证器的签名
     */
    export function verifySignature(opts: {
        signature: Uint8Array_, data: Uint8Array_;
        credentialPublicKey?: Uint8Array_, x509Certificate?: Uint8Array_;
        hashAlgorithm?: COSEALG;
    }): Promise<boolean>;

    /**
     * 允许在测试时模拟返回值
     * @ignore 不要将此内容包含在文档输出中
     */
    export const _verifySignatureInternals: {
        stubThis: (value: Promise<boolean>) => Promise<boolean>;
    };
}

// ================================= 主模块聚合导出 =================================
/**
 * WebAuthn 服务器辅助函数集
 *
 * 本模块提供了一系列用于服务端处理 WebAuthn 认证流程的辅助工具，涵盖：
 * - 数据格式转换（Base64URL、CBOR、PEM、COSE 与 PKCS 互转）
 * - 解析认证器数据（authenticatorData、attestationObject、clientDataJSON）
 * - 提取并验证证书信息（X.509 证书链、吊销状态、扩展字段）
 * - COSE 公钥编解码及类型守卫（支持 OKP/EC2/RSA）
 * - 签名验证、随机挑战值/用户 ID 生成、日志记录等实用功能
 *
 * 所有函数均设计为在 Node.js、Deno、现代浏览器等支持 Web Crypto API 的环境中运行。
 *
 * @module flun-webauthn-server/helpers
 */
declare module 'flun-webauthn-server/helpers' {
    export * from './convertAAGUIDToString.js';
    export * from './convertCertBufferToPEM.js';
    export * from './convertCOSEtoPKCS.js';
    export * from './convertPEMToBytes.js';
    export * from './convertX509PublicKeyToCOSE.js';
    export * from './cose.js';
    export * from './decodeAttestationObject.js';
    export * from './decodeAuthenticatorExtensions.js';
    export * from './decodeClientDataJSON.js';
    export * from './decodeCredentialPublicKey.js';
    export * from './fetch.js';
    export * from './generateChallenge.js';
    export * from './generateUserID.js';
    export * from './getCertificateInfo.js';
    export * from './isCertRevoked.js';
    export * from './logging.js';
    export * from './mapX509SignatureAlgToCOSEAlg.js';
    export * from './matchExpectedRPID.js';
    export * from './parseAuthenticatorData.js';
    export * from './parseBackupFlags.js';
    export * from './toHash.js';
    export * from './validateCertificatePath.js';
    export * from './validateExtFIDOGenCEAAGUID.js';
    export * from './verifySignature.js';
}