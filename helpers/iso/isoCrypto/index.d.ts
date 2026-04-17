import type {
    COSEALG, COSECRV, COSEPublicKey, COSEPublicKeyEC2, COSEPublicKeyOKP, COSEPublicKeyRSA
} from '../../cose.js';
import type { Uint8Array_, Crypto } from '../../../types/index.js';

// ================================= digest.js =================================
/**
 * 生成所提供数据的摘要;
 *
 * @param data - 需要生成摘要的数据
 * @param algorithm - 映射到所需 SHA 算法的 COSE 算法 ID
 */
export declare function digest(data: Uint8Array_, algorithm: COSEALG): Promise<Uint8Array_>;

// ================================= getRandomValues.js =================================
/**
 * 使用与数组长度相等的随机字节填充传入的字节数组;
 *
 * @returns 返回传入的同一个字节数组
 */
export declare function getRandomValues(array: Uint8Array_): Promise<Uint8Array_>;

// ================================= getWebCrypto.js =================================
/**
 * 尝试从当前运行时获取 Crypto API 的实例;
 * 应支持 Node.js 以及其它实现了 Web API 的运行时（如 Deno）;
 */
export declare function getWebCrypto(): Promise<Crypto>;

export declare class MissingWebCrypto extends Error {
    constructor();
}

export declare const _getWebCryptoInternals: {
    stubThisGlobalThisCrypto: () => import("crypto").webcrypto.Crypto;
    setCachedCrypto: (newCrypto: Crypto | undefined) => void;
};

// ================================= importKey.js =================================
export declare function importKey(opts: {
    keyData: JsonWebKey;
    algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
}): Promise<CryptoKey>;

// ================================= mapCoseAlgToWebCryptoAlg.js =================================
/**
 * 将 COSE 算法标识符转换为 WebCrypto API 所期望的对应字符串值
 */
export declare function mapCoseAlgToWebCryptoAlg(alg: COSEALG): SubtleCryptoAlg;

// ================================= mapCoseAlgToWebCryptoKeyAlgName.js =================================
/**
 * 将 COSE 算法标识符（alg ID）转换为 WebCrypto API 所期望的对应密钥算法字符串值
 */
export declare function mapCoseAlgToWebCryptoKeyAlgName(alg: COSEALG): SubtleCryptoKeyAlgName;

// ================================= structs.js =================================
export type SubtleCryptoAlg = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
export type SubtleCryptoCrv = 'P-256' | 'P-384' | 'P-521' | 'Ed25519';
export type SubtleCryptoKeyAlgName = 'ECDSA' | 'Ed25519' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS';

// ================================= unwrapEC2Signature.js =================================
/**
 * 在 WebAuthn 中,EC2 签名被封装在 ASN.1 结构中,因此我们需要从中分离出 r 和 s;
 *
 * 参见 https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 */
export declare function unwrapEC2Signature(signature: Uint8Array_, crv: COSECRV): Uint8Array_;

// ================================= verify.js =================================
/**
 * 使用公钥验证签名,支持 EC2 和 RSA 公钥;
 */
export declare function verify(opts: {
    cosePublicKey: COSEPublicKey, signature: Uint8Array_;
    data: Uint8Array_, shaHashOverride?: COSEALG;
}): Promise<boolean>;

// ================================= verifyEC2.js =================================
/**
 * 使用 EC2 公钥验证签名
 */
export declare function verifyEC2(opts: {
    cosePublicKey: COSEPublicKeyEC2, signature: Uint8Array_;
    data: Uint8Array_, shaHashOverride?: COSEALG;
}): Promise<boolean>;

// ================================= verifyOKP.js =================================
export declare function verifyOKP(opts: {
    cosePublicKey: COSEPublicKeyOKP, signature: Uint8Array_, data: Uint8Array_;
}): Promise<boolean>;

// ================================= verifyRSA.js =================================
/**
 * 使用 RSA 公钥验证签名
 */
export declare function verifyRSA(opts: {
    cosePublicKey: COSEPublicKeyRSA, signature: Uint8Array_;
    data: Uint8Array_, shaHashOverride?: COSEALG;
}): Promise<boolean>;

// ================================= 将全部导出聚合为命名空间 =================================
/**
 * 为了方便外部以 `import * as isoCrypto` 方式导入时获得完整的命名空间类型;
 * 这里显式导出一个包含所有功能的类型别名;
 */
interface IsoCryptoMethods {
    // ================================= digest.js =================================
    /**
     * 生成所提供数据的摘要;
     *
     * @param data - 需要生成摘要的数据
     * @param algorithm - 映射到所需 SHA 算法的 COSE 算法 ID
     */
    digest(data: Uint8Array_, algorithm: COSEALG): Promise<Uint8Array_>;

    // ================================= getRandomValues.js =================================
    /**
     * 使用与数组长度相等的随机字节填充传入的字节数组;
     *
     * @returns 返回传入的同一个字节数组
     */
    getRandomValues(array: Uint8Array_): Promise<Uint8Array_>;
    // ================================= verify.js =================================
    /**
     * 使用公钥验证签名,支持 EC2 和 RSA 公钥;
     */
    verify(opts: {
        cosePublicKey: COSEPublicKey, signature: Uint8Array_;
        data: Uint8Array_, shaHashOverride?: COSEALG;
    }): Promise<boolean>;
}

/**
 * 点击左边加号查看命名空间导出函数
 */
const isoCrypto: IsoCryptoMethods;
export { isoCrypto }