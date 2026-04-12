'use strict';

/**
 * COSE 通用参数和密钥参数标识
 * @enum {number}
 * @see https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
 */
const COSEKEYS = {
    kty: 1, 1: 'kty', alg: 3, 3: 'alg', crv: -1, '-1': 'crv',
    x: -2, '-2': 'x', y: -3, '-3': 'y',
    n: -1, '-1': 'n', // 注意：与 crv 共用 -1，这是 COSE 规范的设计
    e: -2, '-2': 'e'
},
    /**
     * COSE 密钥类型
     * @enum {number}
     * @see https://www.iana.org/assignments/cose/cose.xhtml#key-type
     */
    COSEKTY = { OKP: 1, 1: 'OKP', EC2: 2, 2: 'EC2', RSA: 3, 3: 'RSA' },

    /**
     * COSE 椭圆曲线参数
     * @enum {number}
     * @see https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
     */
    COSECRV = {
        P256: 1, 1: 'P256', P384: 2, 2: 'P384', P521: 3, 3: 'P521',
        ED25519: 6, 6: 'ED25519', SECP256K1: 8, 8: 'SECP256K1',
    },

    /**
     * COSE 算法标识
     * @enum {number}
     * @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     */
    COSEALG = {
        ES256: -7, '-7': 'ES256', EdDSA: -8, '-8': 'EdDSA',
        ES384: -35, '-35': 'ES384', ES512: -36, '-36': 'ES512',
        PS256: -37, '-37': 'PS256', PS384: -38, '-38': 'PS384', PS512: -39, '-39': 'PS512',
        ES256K: -47, '-47': 'ES256K',
        RS256: -257, '-257': 'RS256', RS384: -258, '-258': 'RS384', RS512: -259, '-259': 'RS512',
        RS1: -65535, '-65535': 'RS1'
    };

/**
 * 判断一个 COSE 公钥是否为 OKP 密钥对
 */
function isCOSEPublicKeyOKP(cosePublicKey) {
    const kty = cosePublicKey.get(COSEKEYS.kty);
    return isCOSEKty(kty) && kty === COSEKTY.OKP;
}

/**
 * 判断一个 COSE 公钥是否为 EC2 密钥对
 */
function isCOSEPublicKeyEC2(cosePublicKey) {
    const kty = cosePublicKey.get(COSEKEYS.kty);
    return isCOSEKty(kty) && kty === COSEKTY.EC2;
}

/**
 * 判断一个 COSE 公钥是否为 RSA 密钥对
 */
function isCOSEPublicKeyRSA(cosePublicKey) {
    const kty = cosePublicKey.get(COSEKEYS.kty);
    return isCOSEKty(kty) && kty === COSEKTY.RSA;
}

/**
 * 判断给定的值是否为有效的 COSE 密钥类型（kty）
 *
 * @param {unknown} kty - 待检测的密钥类型值
 * @returns {boolean} 如果该值是有效的 COSEKTY 枚举值返回 true；否则返回 false
 * @see {@link https://www.iana.org/assignments/cose/cose.xhtml#key-type|COSE Key Type Registry}
 */
function isCOSEKty(kty) {
    return Object.values(COSEKTY).includes(kty);
}

/**
 * 判断给定的值是否为有效的 COSE 椭圆曲线参数（crv）
 *
 * @param {unknown} crv - 待检测的曲线参数值
 * @returns {boolean} 如果该值是有效的 COSECRV 枚举值返回 true；否则返回 false
 * @see {@link https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves|COSE Elliptic Curves Registry}
 */
function isCOSECrv(crv) {
    return Object.values(COSECRV).includes(crv);
}

/**
 * 判断给定的值是否为有效的 COSE 算法标识（alg）
 *
 * @param {unknown} alg - 待检测的算法标识值
 * @returns {boolean} 如果该值是有效的 COSEALG 枚举值返回 true；否则返回 false
 * @see {@link https://www.iana.org/assignments/cose/cose.xhtml#algorithms|COSE Algorithms Registry}
 */
function isCOSEAlg(alg) {
    return Object.values(COSEALG).includes(alg);
}

// 集中导出
module.exports = {
    COSEKEYS, COSEKTY, COSECRV, COSEALG,
    isCOSEPublicKeyOKP, isCOSEPublicKeyEC2, isCOSEPublicKeyRSA, isCOSEKty, isCOSECrv, isCOSEAlg
};