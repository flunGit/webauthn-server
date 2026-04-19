import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import { validateCertificatePath, convertCertBufferToPEM, toHash, convertCOSEtoPKCS, concat, areEqual } from '../../helpers/index.js';

/**
 * 验证 Apple 类型的证明（attestation）
 * - 查看定义:@see {@link verifyAttestationApple}
 */
const verifyAttestationApple = async options => {
    const { attStmt, authData, clientDataHash, credentialPublicKey, rootCertificates } = options, x5c = attStmt.get('x5c');
    if (!x5c) throw new Error('证明声明中未提供证明证书 (Apple)');

    /**
     * 验证证书链
     */
    try {
        await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
    } catch (err) {
        throw new Error(`${err.message} (Apple)`);
    }

    /**
     * 将证书扩展中的 nonce 与计算出的 nonce 进行比较
     */
    const parsedCredCert = AsnParser.parse(x5c[0], Certificate),
        { extensions, subjectPublicKeyInfo } = parsedCredCert.tbsCertificate;
    if (!extensions) throw new Error('凭证证书缺少扩展字段 (Apple)');

    const extCertNonce = extensions.find((ext) => ext.extnID === '1.2.840.113635.100.8.2');
    if (!extCertNonce) throw new Error('凭证证书缺少“1.2.840.113635.100.8.2”扩展 (Apple)');

    const nonceToHash = concat([authData, clientDataHash]), nonce = await toHash(nonceToHash),
        /**
         * 忽略前六个 ASN.1 结构字节，这些字节将 nonce 定义为 OCTET STRING。
         * 应去除 <Buffer 30 24 a1 22 04 20>
         *
         * TODO: 尝试让 @peculiar (GitHub) 为 “1.2.840.113635.100.8.2” 添加 schema，
         * 目前该扩展似乎没有公开文档说明其定义位置……
         */
        extNonce = new Uint8Array(extCertNonce.extnValue.buffer).slice(6);
    if (!areEqual(nonce, extNonce)) throw new Error('凭证证书中的 nonce 与期望值不符 (Apple)');

    /**
     * 验证凭证公钥是否与凭证证书的主体公钥匹配
     */
    const credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey),
        credCertSubjectPublicKey = new Uint8Array(subjectPublicKeyInfo.subjectPublicKey);

    if (!areEqual(credPubKeyPKCS, credCertSubjectPublicKey)) throw new Error('凭证公钥不等于凭证证书中的公钥 (Apple)');
    return true;
};

export { verifyAttestationApple };