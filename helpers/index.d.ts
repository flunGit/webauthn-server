import { Certificate } from '@peculiar/asn1-x509';
import type { Uint8Array_ } from '../types/index.js';
import {
    digest, getRandomValues, verify, fromBuffer, utf8Tob64url, toBuffer, toBase64, b64urlToUtf8, isBase64,
    isBase64URL, trimPadding, fromHex, utf8Tobytes, asciiToBytes, toHex, toDataView, bytesToUtf8, areEqual, concat
} from './iso/index.js';
import { convertAAGUIDToString } from './convertAAGUIDToString.js';
import { convertCertBufferToPEM } from './convertCertBufferToPEM.js';
import { convertCOSEtoPKCS } from './convertCOSEtoPKCS.js';
import { convertPEMToBytes } from './convertPEMToBytes.js';
import { convertX509PublicKeyToCOSE } from './convertX509PublicKeyToCOSE.js';
import {
    COSEKEYS, COSEKTY, COSECRV, COSEALG,
    isCOSEPublicKeyOKP, isCOSEPublicKeyEC2, isCOSEPublicKeyRSA, isCOSEKty, isCOSECrv, isCOSEAlg
} from './cose.js';
import { _decodeAttestationObjectInternals, decodeAttestationObject } from './decodeAttestationObject.js';
import { decodeAuthenticatorExtensions } from './decodeAuthenticatorExtensions.js';
import { decodeClientDataJSON, _decodeClientDataJSONInternals } from './decodeClientDataJSON.js';
import { _decodeCredentialPublicKeyInternals, decodeCredentialPublicKey } from './decodeCredentialPublicKey.js';
import { _fetchInternals, fetch } from './fetch.js';
import { _generateChallengeInternals, generateChallenge } from './generateChallenge.js';
import { _generateUserIDInternals, generateUserID } from './generateUserID.js';
import { getCertificateInfo } from './getCertificateInfo.js';
import { isCertRevoked } from './isCertRevoked.js';
import { getLogger } from './logging.js';
import { mapX509SignatureAlgToCOSEAlg } from './mapX509SignatureAlgToCOSEAlg.js';
import { matchExpectedRPID, UnexpectedRPIDHash } from './matchExpectedRPID.js';
import { _parseAuthenticatorDataInternals, parseAuthenticatorData } from './parseAuthenticatorData.js';
import { parseBackupFlags, InvalidBackupFlags } from './parseBackupFlags.js';
import { toHash } from './toHash.js';
import { validateCertificatePath, InvalidSubjectAndIssuer } from './validateCertificatePath.js';
import { validateExtFIDOGenCEAAGUID } from './validateExtFIDOGenCEAAGUID.js';
import { _verifySignatureInternals, verifySignature } from './verifySignature.js';
import { verifyMDSBlob } from '../metadata/index.js';

// ================================= convertAAGUIDToString.js =================================
/**
 * ```js
 * // 文件导出内容:
 * convertAAGUIDToString(); // 将 authData 中的 aaguid 缓冲区转换为 UUID 字符串
 * ```
 * ---
 * - 查看定义:@see {@link convertAAGUIDToString}
 */
module './convertAAGUIDToString.js' {
    export * from './convertAAGUIDToString.js';
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
module './convertCertBufferToPEM.js' {
    export * from './convertCertBufferToPEM.js';
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
module './convertCOSEtoPKCS.js' {
    export * from './convertCOSEtoPKCS.js';
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
module './convertPEMToBytes.js' {
    export * from './convertPEMToBytes.js';
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
module './convertX509PublicKeyToCOSE.js' {
    export * from './convertX509PublicKeyToCOSE.js';
}

// ================================= cose.js =================================
/**
 * ```js
 * // 文件导出内容:
 *  // 类型定义
 *  type COSEPublicKey;type COSEPublicKeyOKP;type COSEPublicKeyEC2;type COSEPublicKeyRSA;
 *
 *  // 枚举常量
 *  enum COSEKEYS{};enum COSEKTY{};enum COSECRV,{};enum COSEALG{};
 *
 *  // 类型守卫函数
 *  isCOSEPublicKeyOKP(), isCOSEPublicKeyEC2(), isCOSEPublicKeyRSA();
 *  isCOSEKty(), isCOSECrv(), isCOSEAlg();
 * ```
 * ---
 * - 查看定义:@see {@link COSEPublicKey}、{@link COSEPublicKeyOKP}、{@link COSEPublicKeyEC2}、{@link COSEPublicKeyRSA}、
 *  {@link COSEKEYS}、{@link COSEKTY}、{@link COSECRV}、{@link COSEALG}、{@link isCOSEPublicKeyOKP}、
 *  {@link isCOSEPublicKeyEC2}、{@link isCOSEPublicKeyRSA}、{@link isCOSEKty}、{@link isCOSECrv}、{@link isCOSEAlg}
 */
module './cose.js' {
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

    export * from './cose.js';
}

// ================================= decodeAttestationObject.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type AttestationFormat; type AttestationObject,;type AttestationStatement;
 *
 * // 函数
 * decodeAttestationObject();
 * ```
 * ---
 * - 查看定义:@see {@link decodeAttestationObject}、{@link AttestationFormat}、{@link AttestationObject}、{@link AttestationStatement}
 */
module './decodeAttestationObject.js' {
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

    export * from './decodeAttestationObject.js';
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
module './decodeAuthenticatorExtensions.js' {
    /**
     * 尝试支持 WebAuthn 中可能未知的身份验证器扩展
     */
    export type AuthenticationExtensionsAuthenticatorOutputs = unknown;
    export * from './decodeAuthenticatorExtensions.js';
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
module './decodeClientDataJSON.js' {
    export type ClientDataJSON = {
        type: string, challenge: string, origin: string;
        crossOrigin?: boolean;
        tokenBinding?: { id?: string; status: 'present' | 'supported' | 'not-supported' };
    };
    export * from './decodeClientDataJSON.js';
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
module './decodeCredentialPublicKey.js' {
    export * from './decodeCredentialPublicKey.js';
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
module './fetch.js' {
    export * from './fetch.js';
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
module './generateChallenge.js' {
    export * from './generateChallenge.js';
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
module './generateUserID.js' {
    export * from './generateChallenge.js';
}

// ================================= getCertificateInfo.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type CertificateInfo;type Issuer;type Subject;
 *
 * // 函数
 * getCertificateInfo();
 * ```
 * ---
 * - 查看定义:@see {@link getCertificateInfo}、{@link CertificateInfo}、{@link Issuer}、{@link Subject}
 */
module './getCertificateInfo.js' {
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

    export * from './getCertificateInfo.js';
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
module './isCertRevoked.js' {
    export * from './isCertRevoked.js';
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
module './logging.js' {
    export * from './logging.js';
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
module './mapX509SignatureAlgToCOSEAlg.js' {
    export * from './mapX509SignatureAlgToCOSEAlg.js';
}

// ================================= matchExpectedRPID.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类
 * class UnexpectedRPIDHash{}; // 当响应中的 RP ID 哈希值与所有预期的 RP ID 均不匹配时抛出的错误;
 *
 * // 函数
 * matchExpectedRPID();       // 遍历所有预期的 RP ID,找出与响应中哈希值匹配的项,并返回对应的原始 RP ID
 * ```
 * ---
 * - 查看定义:@see {@link matchExpectedRPID}、{@link UnexpectedRPIDHash}
 */
module './matchExpectedRPID.js' {
    export * from './matchExpectedRPID.js';
}

// ================================= parseAuthenticatorData.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类型定义
 * type ParsedAuthenticatorData;
 *
 * // 函数
 * parseAuthenticatorData(); // 解析认证数据（Attestation 中包含的 authData 缓冲区）
 * ```
 * ---
 * - 查看定义:@see {@link parseAuthenticatorData}、{@link ParsedAuthenticatorData}
 */
module './parseAuthenticatorData.js' {
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

    export * from './parseAuthenticatorData.js';
}

// ================================= parseBackupFlags.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类
 * class InvalidBackupFlags{}; // 当解析备份标志（be/bs）时遇到无效组合时抛出的错误;
 *
 * // 函数
 * parseBackupFlags();         // 解析身份验证器中的第 3 位和第 4 位标志是否匹配;
 * ```
 * ---
 * - 查看定义:@see {@link parseBackupFlags}、{@link InvalidBackupFlags}
 */
module './parseBackupFlags.js' {
    export * from './parseBackupFlags.js'
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
module './toHash.js' {
    export * from './toHash.js';
}

// ================================= validateCertificatePath.js =================================
/**
 * ```js
 * // 文件导出内容:
 * // 类
 * class InvalidSubjectAndIssuer{}; // 当证书链中某一证书的颁发者无法为下一证书签名,或根证书不自签名时,则抛出错误;
 *
 * // 函数
 * validateCertificatePath();      // 遍历 PEM 证书数组,确保形成有效的证书链
 * ```
 * ---
 * - 查看定义:@see {@link validateCertificatePath}、{@link InvalidSubjectAndIssuer}
 */
module './validateCertificatePath.js' {
    export * from './validateCertificatePath.js'
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
module './validateExtFIDOGenCEAAGUID.js' {
    export * from './validateExtFIDOGenCEAAGUID.js'
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
module './verifySignature.js' {
    export * from './verifySignature.js';
}

// ================================= 主模块聚合导出 =================================
/**
 * ```js
 * // iso目录工具:
 * digest();                     // 生成所提供数据的摘要;
 * getRandomValues();            // 使用与数组长度相等的随机字节填充传入的字节数组;
 * verify();                     // 使用公钥验证签名,支持 EC2 和 RSA 公钥;
 * fromBuffer();                 // 将给定的 ArrayBuffer编码为 Base64URL
 * utf8Tob64url();               // 将 UTF-8字符串编码为 base64url
 * toBuffer();                   // 将 Base64URL编码的字符串解码为 ArrayBuffer
 * toBase64();                   // 将 Base64URL字符串转换为标准 base64
 * b64urlToUtf8();               // 将 base64url字符串解码为其原始的 UTF-8
 * isBase64();                   // 检查是否为 base64编码
 * isBase64URL();                // 检查是否为 base64url编码
 * trimPadding();                // 移除 base64url 编码字符串中可选的填充字符
 * decodeFirst();                // 解码 CBOR 数据的第一个项
 * encode();                     // 将数据编码为 CBOR
 * fromHex();                    // 从十六进制字符串创建 Uint8Array
 * utf8Tobytes();                // 将 UTF-8 字符串编码为 Uint8Array
 * asciiToBytes();               // 将 ASCII 字符串转换为 Uint8Array
 * toHex();                      // 转换为十六进制字符串
 * toDataView();                 // 转换为 DataView 对象
 * bytesToUtf8();                // 将 Uint8Array 解码为 UTF-8 字符串
 * areEqual();                   // 判断两个 Uint8Array 是否相等
 * concat();                     // 合并多个 Uint8Array
 *
 * verifyMDSBlob();              // 对 BLOB 进行真实性与完整性验证
 * // 转换函数
 * convertAAGUIDToString();      // 将 authData 中的 aaguid 缓冲区转换为 UUID 字符串
 * convertCertBufferToPEM();     // 将缓冲区转换为 OpenSSL 兼容的 PEM 文本格式
 * convertCOSEtoPKCS();          // 接收 COSE 编码的公钥，并将其转换为 PKCS 密钥
 * convertPEMToBytes();          // 将 PEM 格式的证书转换为字节数组
 * convertX509PublicKeyToCOSE(); // 从 X.509 证书（DER 格式）中提取公钥，并将其转换为 COSE 公钥结构
 *
 * // COSE 公钥处理
 * // 枚举常量
 * enum COSEKEYS{}; enum COSEKTY{}; enum COSECRV{}; enum COSEALG{};
 * // 类型守卫函数
 * isCOSEPublicKeyOKP(); isCOSEPublicKeyEC2(); isCOSEPublicKeyRSA(); isCOSEKty(); isCOSECrv(); isCOSEAlg();
 *
 * // 解码与解析函数
 * decodeAttestationObject();       // 将 AttestationObject 缓冲区转换为对应的对象
 * decodeAuthenticatorExtensions(); // 将身份验证器扩展数据缓冲区转换为相应的对象
 * decodeClientDataJSON();          // 将身份验证器的 base64url 编码的 clientDataJSON 解码为 JSON
 * decodeCredentialPublicKey();     // 将 WebAuthn 凭证公钥（CBOR 编码的 COSE 公钥）解码为 COSEPublicKey Map 对象
 *
 * // 证书处理
 * getCertificateInfo();            // 提取 PEM 证书信息
 * isCertRevoked();                 // 从证书中获取证书吊销列表（CRL），并将其中的序列号与 CRL 内已吊销证书的序列号进行比对
 * validateCertificatePath();       // 遍历 PEM 证书数组，确保形成有效的证书链
 * validateExtFIDOGenCEAAGUID();    // 查找 FIDO Gen CE AAGUID 证书扩展并比对 AAGUID
 * class InvalidSubjectAndIssuer{}; // 当证书链中某一证书的颁发者无法为下一证书签名,或根证书不自签名时,则抛出错误;
 *
 * // 认证器数据解析
 * parseAuthenticatorData();       // 解析 Attestation 中包含的 authData 缓冲区，使其变得可读
 * parseBackupFlags();             // 解析身份验证器中的第 3 位和第 4 位，返回匹配标志
 * class InvalidBackupFlags{};     // 当解析备份标志（be/bs）时遇到无效组合时抛出的错误;
 *
 * // 签名与校验
 * verifySignature();              // 验证身份验证器的签名
 * toHash();                       // 返回给定数据的哈希摘要，默认使用 SHA-256
 * mapX509SignatureAlgToCOSEAlg(); // 将 X.509 签名算法 OID 映射到 COSE 算法 ID
 *
 * // 工具与辅助
 * fetch();                         // 一个用于通过标准 fetch 请求数据的简单方法，可在多种运行时环境中工作
 * generateChallenge();             // 生成一个合适的随机值，用作证明或断言的挑战值
 * generateUserID();                // 生成一个适合作为用户 ID 的随机值
 * matchExpectedRPID();             // 遍历每一个预期的 RP ID，尝试找到匹配项，返回与响应中的哈希值匹配的未哈希 RP ID
 * getLogger();                     // 生成一个 debug 日志记录器的实例，基于 "flunWebauthn" 扩展
 * class UnexpectedRPIDHash{};      // 当响应中的 RP ID 哈希值与所有预期的 RP ID 均不匹配时抛出的错误;
 * ```
 * ---
 * - 查看定义@see :
 * - iso目录工具:{@link digest}、{@link getRandomValues}、{@link verify }、{@link fromBuffer}、{@link utf8Tob64url}、
 * {@link toBuffer}、{@link toBase64}、{@link b64urlToUtf8}、{@link isBase64}、{@link isBase64URL}、{@link trimPadding}、
 * {@link fromHex}、{@link utf8Tobytes}、{@link asciiToBytes}、{@link toHex}、{@link toDataView}、 {@link bytesToUtf8}、
 * {@link areEqual}、{@link concat}
 * - BLOB验证函数:{@link verifyMDSBlob};
 * - 转换函数:{@link convertAAGUIDToString}、{@link convertCertBufferToPEM}、{@link convertCOSEtoPKCS}、
 *  {@link convertPEMToBytes}、{@link convertX509PublicKeyToCOSE}
 * - COSE 公钥 {@link COSEKEYS}、{@link COSEKTY}、{@link COSECRV}、{@link COSEALG}、{@link isCOSEPublicKeyOKP}、
 * {@link isCOSEPublicKeyEC2}、{@link isCOSEPublicKeyRSA}、{@link isCOSEKty}、{@link isCOSECrv}、{@link isCOSEAlg}
 * - 解码与解析：{@link decodeAttestationObject}、{@link decodeAuthenticatorExtensions}、{@link decodeClientDataJSON}、
 * {@link decodeCredentialPublicKey}
 * - 证书处理：{@link getCertificateInfo}、{@link isCertRevoked}、{@link validateCertificatePath}、
 * {@link validateExtFIDOGenCEAAGUID}、{@link InvalidSubjectAndIssuer}
 * - 认证器数据解析：{@link parseAuthenticatorData}、{@link parseBackupFlags}、 {@link InvalidBackupFlags}
 * - 签名与校验：{@link verifySignature}、{@link toHash}、{@link mapX509SignatureAlgToCOSEAlg}
 * - 工具与辅助：{@link fetch}、{@link generateChallenge}、{@link generateUserID}、{@link matchExpectedRPID}、
 * {@link getLogger}、{@link UnexpectedRPIDHash}
 */
module './index' { }
export * from './iso/index.js';
export * from './convertAAGUIDToString.js';
export * from './convertCertBufferToPEM.js';
export * from './convertCOSEtoPKCS.js';
export * from './convertPEMToBytes.js';
export * from './convertX509PublicKeyToCOSE.js';
export * from './cose.js';
export * from './decodeAttestationObject.js';
export * from './decodeClientDataJSON.js';
export * from './decodeCredentialPublicKey.js';
export * from './fetch.js';
export * from './generateChallenge.js';
export * from './generateUserID.js';
export * from './getCertificateInfo.js';
export * from './isCertRevoked.js';
export * from './logging.js';
export * from './matchExpectedRPID.js';
export * from './parseAuthenticatorData.js';
export * from './parseBackupFlags.js';
export * from './toHash.js';
export * from './validateCertificatePath.js';
export * from './validateExtFIDOGenCEAAGUID.js';
export * from './verifySignature.js';