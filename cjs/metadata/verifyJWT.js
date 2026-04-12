'use strict';

const { convertX509PublicKeyToCOSE } = require('../helpers/convertX509PublicKeyToCOSE.js'),
    { isoUint8Array, isoBase64URL } = require('../helpers/iso/index.js'),
    { isCOSEPublicKeyEC2, isCOSEPublicKeyRSA, COSEKEYS, COSEALG } = require('../helpers/cose.js'),
    { verifyEC2 } = require('../helpers/iso/isoCrypto/verifyEC2.js'),
    { verifyRSA } = require('../helpers/iso/isoCrypto/verifyRSA.js');

/**
 * 用于 FIDO MDS JWT 的轻量级验证。支持 EC2 和 RSA 算法;
 *
 * 如果未来需要支持更多 JWS 算法，可参考以下列表：
 *
 * https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1
 *
 * （摘自 https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1）
 *
 * @param {string} jwt - 待验证的 JWT 字符串（格式为 header.payload.signature）
 * @param {string|Buffer|Uint8Array} leafCert - X.509 叶子证书（PEM 格式或二进制数据）
 * @returns {Promise<boolean>} 验证通过返回 true，失败则抛出异常
 */
async function verifyJWT(jwt, leafCert) {
    // 将 X.509 证书转换为 COSE 公钥格式,构造签名数据：ASCII 编码的 header.payload,将 Base64URL 编码的签名转换为 Uint8Array
    const [header, payload, signature] = jwt.split('.'), certCOSE = convertX509PublicKeyToCOSE(leafCert),
        data = isoUint8Array.fromUTF8String(`${header}.${payload}`), signatureBytes = isoBase64URL.toBuffer(signature);

    // 根据公钥类型选择对应的验证方法
    if (isCOSEPublicKeyEC2(certCOSE))
        return verifyEC2({ data, signature: signatureBytes, cosePublicKey: certCOSE, shaHashOverride: COSEALG.ES256 });
    else if (isCOSEPublicKeyRSA(certCOSE)) return verifyRSA({ data, signature: signatureBytes, cosePublicKey: certCOSE });

    // 不支持的密钥类型
    const kty = certCOSE.get(COSEKEYS.kty);
    throw new Error(`不支持使用 kty 为 ${kty} 的公钥进行 JWT 验证`);
}

module.exports = { verifyJWT };