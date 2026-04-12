'use strict';

const { AsnParser } = require('@peculiar/asn1-schema'), { Certificate } = require('@peculiar/asn1-x509'),
    { validateCertificatePath, convertCertBufferToPEM, toHash, convertCOSEtoPKCS, isoUint8Array
    } = require('../../helpers/index.js'), { concat, areEqual } = isoUint8Array;

/**
 * 验证 Apple 匿名证明
 * @param {Object} options 验证选项
 * @param {Map} options.attStmt 证明语句
 * @param {Uint8Array} options.authData 认证器数据
 * @param {Uint8Array} options.clientDataHash 客户端数据哈希
 * @param {Uint8Array} options.credentialPublicKey 凭证公钥（COSE 格式）
 * @param {string[]} options.rootCertificates 根证书列表（PEM 格式）
 * @returns {Promise<boolean>} 验证通过返回 true
 */
async function verifyAttestationApple(options) {
    const { attStmt, authData, clientDataHash, credentialPublicKey, rootCertificates } = options, x5c = attStmt.get('x5c');
    if (!x5c) throw new Error('证明声明中未提供证明证书 (Apple)');

    /**
     * 验证证书链路径
     */
    try {
        await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
    } catch (err) { throw new Error(`${err.message} (Apple)`); }

    /**
     * 对比证书扩展中的 nonce 与计算出的 nonce
     */
    const parsedCredCert = AsnParser.parse(x5c[0], Certificate),
        { extensions, subjectPublicKeyInfo } = parsedCredCert.tbsCertificate;
    if (!extensions) throw new Error('凭证证书缺少扩展字段 (Apple)');

    // Apple 扩展 OID: 1.2.840.113635.100.8.2
    const extCertNonce = extensions.find((ext) => ext.extnID === '1.2.840.113635.100.8.2');
    if (!extCertNonce) throw new Error('凭证证书缺少 "1.2.840.113635.100.8.2" 扩展 (Apple)');

    const nonceToHash = concat([authData, clientDataHash]), nonce = await toHash(nonceToHash),
        /**
         * 忽略前 6 个 ASN.1 结构字节，它们将 nonce 定义为 OCTET STRING。
         * 应裁掉 <Buffer 30 24 a1 22 04 20>
         *
         * TODO: 待找到 "1.2.840.113635.100.8.2" 的定义（目前似乎没有公开文档），
         *       尝试让 @peculiar（GitHub）为其添加 schema。
         */
        extNonce = new Uint8Array(extCertNonce.extnValue.buffer).slice(6);
    if (!areEqual(nonce, extNonce)) throw new Error('凭证证书中的 nonce 值与预期不符 (Apple)');

    /**
     * 验证凭证公钥与证书中的 Subject Public Key 是否匹配
     */
    const credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey),
        credCertSubjectPublicKey = new Uint8Array(subjectPublicKeyInfo.subjectPublicKey);

    if (!areEqual(credPubKeyPKCS, credCertSubjectPublicKey)) throw new Error('凭证公钥与证书公钥不一致(Apple)');
    return true;
}

module.exports = { verifyAttestationApple };