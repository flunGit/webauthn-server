'use strict';

// 解构引入所有需要的函数和对象
const { AsnParser } = require('@peculiar/asn1-schema'), { Certificate } = require('@peculiar/asn1-x509'),
    { id_ce_keyDescription, KeyDescription } = require('@peculiar/asn1-android'),
    { convertCertBufferToPEM, validateCertificatePath, verifySignature, convertCOSEtoPKCS, isoUint8Array, isCOSEAlg
    } = require('../../helpers/index.js'), { MetadataService } = require('../../services/metadataService.js'),
    { verifyAttestationWithMetadata } = require('../../metadata/verifyAttestationWithMetadata.js'),
    { areEqual, concat } = isoUint8Array;

/**
 * 验证 fmt 为 'android-key' 的证明响应
 */
async function verifyAttestationAndroidKey(options) {
    const { authData, clientDataHash, attStmt, credentialPublicKey, aaguid, rootCertificates } = options,
        x5c = attStmt.get('x5c'), sig = attStmt.get('sig'), alg = attStmt.get('alg');

    if (!x5c) throw new Error('证明声明中未提供证明证书 (Android Key)');
    if (!sig) throw new Error('证明声明中未提供证明签名 (Android Key)');
    if (!alg) throw new Error(`证明声明中缺少 alg 字段 (Android Key)`);
    if (!isCOSEAlg(alg)) throw new Error(`证明声明中包含无效的算法标识 ${alg} (Android Key)`);

    /**
     * 验证 x5c 中第一个证书的公钥是否与 authenticatorData 中
     * attestedCredentialData 内的 credentialPublicKey 匹配。
     */
    const parsedCert = AsnParser.parse(x5c[0], Certificate),
        parsedCertPubKey = new Uint8Array(parsedCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey),
        credPubKeyPKCS = convertCOSEtoPKCS(credentialPublicKey);
    if (!areEqual(credPubKeyPKCS, parsedCertPubKey)) throw new Error('凭证公钥与叶子证书公钥不匹配 (Android Key)');

    /**
     * 验证证书扩展数据中的 attestationChallenge 字段是否与 clientDataHash 完全一致。
     */
    const extKeyStore = parsedCert.tbsCertificate.extensions?.find(ext => ext.extnID === id_ce_keyDescription);
    if (!extKeyStore) throw new Error('证书中未包含 KeyStore 扩展 (Android Key)');

    const parsedExtKeyStore = AsnParser.parse(extKeyStore.extnValue, KeyDescription),
        { attestationChallenge, teeEnforced, softwareEnforced } = parsedExtKeyStore;
    if (!areEqual(new Uint8Array(attestationChallenge.buffer), clientDataHash))
        throw new Error('证明挑战值与客户端数据哈希不一致 (Android Key)');

    /**
     * AuthorizationList.allApplications 字段不应出现在 softwareEnforced 或 teeEnforced 中,
     * 因为 PublicKeyCredential 必须限定于 RP ID;
     */
    if (teeEnforced.allApplications !== undefined)
        throw new Error('teeEnforced 中包含了 "allApplications [600]" 标签 (Android Key)');
    if (softwareEnforced.allApplications !== undefined)
        throw new Error('softwareEnforced 中包含了 "allApplications [600]" 标签 (Android Key)');

    const statement = await MetadataService.getStatement(aaguid);
    if (statement) {
        try {
            await verifyAttestationWithMetadata({ statement, credentialPublicKey, x5c, attestationStatementAlg: alg });
        } catch (err) {
            throw new Error(`${err.message} (Android Key)`, { cause: err });
        }
    } else {
        /**
         * 验证 x5c 是否包含完整的证书链;
         */
        const x5cNoRootPEM = x5c.slice(0, -1).map(convertCertBufferToPEM),
            x5cRootPEM = x5c.slice(-1).map(convertCertBufferToPEM);

        try {
            await validateCertificatePath(x5cNoRootPEM, x5cRootPEM);
        } catch (err) {
            throw new Error(`${err.message} (Android Key)`, { cause: err });
        }

        /**
         * 确保根证书是 Google 硬件证明根证书之一
         *
         * https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
         */
        if (rootCertificates.length > 0 && rootCertificates.indexOf(x5cRootPEM[0]) < 0)
            throw new Error('x5c 根证书不是已知的受信任根证书 (Android Key)');
    }

    /**
     * 验证 sig 是否为使用 x5c 中第一个证书的公钥以及 alg 指定的算法，
     * 对 authenticatorData 和 clientDataHash 拼接数据的有效签名。
     */
    const signatureBase = concat([authData, clientDataHash]);
    return verifySignature({ signature: sig, data: signatureBase, x509Certificate: x5c[0], hashAlgorithm: alg });
}

module.exports = { verifyAttestationAndroidKey };