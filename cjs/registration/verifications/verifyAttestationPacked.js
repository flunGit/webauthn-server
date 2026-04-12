'use strict';

const { isCOSEAlg, convertCertBufferToPEM, validateCertificatePath, getCertificateInfo, validateExtFIDOGenCEAAGUID,
    verifySignature, isoUint8Array } = require('../../helpers/index.js'),
    { MetadataService } = require('../../services/metadataService.js'),
    { verifyAttestationWithMetadata } = require('../../metadata/verifyAttestationWithMetadata.js');

/**
 * 验证 fmt 为 'packed' 的认证响应
 *
 * @param {object} options 验证选项
 * @param {Map} options.attStmt 认证声明
 * @param {Uint8Array} options.clientDataHash 客户端数据哈希
 * @param {Uint8Array} options.authData 认证器数据
 * @param {Uint8Array} options.credentialPublicKey 凭证公钥
 * @param {Uint8Array} options.aaguid AAGUID
 * @param {string[]} options.rootCertificates 根证书列表（PEM 格式）
 * @returns {Promise<boolean>} 验证是否通过
 */
async function verifyAttestationPacked(options) {
    const { attStmt, clientDataHash, authData, credentialPublicKey, aaguid, rootCertificates, } = options,
        sig = attStmt.get('sig'), x5c = attStmt.get('x5c'), alg = attStmt.get('alg');

    if (!sig) throw new Error('认证声明中缺少签名 (Packed)');
    if (!alg) throw new Error('认证声明中未包含 alg (Packed)');
    if (!isCOSEAlg(alg)) throw new Error(`认证声明包含无效的算法标识 ${alg} (Packed)`);

    // 构建签名基础数据：authData + clientDataHash
    const signatureBase = isoUint8Array.concat([authData, clientDataHash]);
    let verified = false;

    if (x5c) {
        // 存在 x5c 证书链，按完全认证模式验证
        const certInfo = getCertificateInfo(x5c[0]), { subject, basicConstraintsCA, version, notBefore, notAfter,
            parsedCertificate, } = certInfo, { OU, CN, O, C } = subject;

        if (OU !== 'Authenticator Attestation') throw new Error('证书 OU 字段不为"Authenticator Attestation"(Packed|Full)');
        if (!CN) throw new Error('证书 CN 字段为空 (Packed|Full)');
        if (!O) throw new Error('证书 O 字段为空 (Packed|Full)');
        if (!C || C.length !== 2) throw new Error('证书 C 字段不是两位 ISO 3166 国家代码 (Packed|Full)');
        if (basicConstraintsCA) throw new Error('证书基本约束 CA 不为 `false` (Packed|Full)');
        if (version !== 2) throw new Error('证书版本不是 `3`（ASN.1 值为 2） (Packed|Full)');

        // 检查证书有效期
        let now = new Date();
        if (notBefore > now) throw new Error(`证书有效期起始于 "${notBefore.toString()}"，当前时间不可用 (Packed|Full)`);

        now = new Date();
        if (notAfter < now) throw new Error(`证书有效期截止于 "${notAfter.toString()}"，已过期 (Packed|Full)`);

        // 验证证书扩展中的 AAGUID 是否匹配
        try {
            await validateExtFIDOGenCEAAGUID(parsedCertificate.tbsCertificate.extensions, aaguid);
        } catch (err) { throw new Error(`${err.message} (Packed|Full)`); }

        // 尝试通过元数据服务进行验证
        const statement = await MetadataService.getStatement(aaguid);
        if (statement) {
            // x5c 存在表示完全认证,检查元数据是否支持 basic_full 类型
            if (statement.attestationTypes.indexOf('basic_full') < 0) throw new Error('元数据声明不支持完全认证(Packed|Full)');
            try {
                await verifyAttestationWithMetadata({ statement, credentialPublicKey, x5c, attestationStatementAlg: alg });
            } catch (err) { throw new Error(`${err.message} (Packed|Full)`); }
        } else {
            // 无元数据时,通过根证书验证证书链
            try {
                const pemCerts = x5c.map(convertCertBufferToPEM);
                await validateCertificatePath(pemCerts, rootCertificates);
            } catch (err) { throw new Error(`${err.message} (Packed|Full)`); }
        }

        // 使用叶证书验证签名
        verified = await verifySignature({ signature: sig, data: signatureBase, x509Certificate: x5c[0] });
    }
    // 不存在证书链，按自认证模式验证（使用凭证公钥）
    else verified = await verifySignature({ signature: sig, data: signatureBase, credentialPublicKey, hashAlgorithm: alg });

    return verified;
}

module.exports = { verifyAttestationPacked };