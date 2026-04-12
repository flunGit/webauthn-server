'use strict';

const { AuthorityKeyIdentifierExtension, CRLDistributionPointsExtension, SubjectKeyIdentifierExtension, X509Crl } = require('@peculiar/x509'),
    { fetch } = require('./fetch.js'), cacheRevokedCerts = {};
/**
 * 从证书中获取 CRL 分发点，下载 CRL 并比对证书序列号是否存在于吊销列表中
 *
 * CRL 证书结构参考：https://tools.ietf.org/html/rfc5280#page-117
 *
 * @param  cert -待检查的证书
 * @returns {Promise<boolean>} 如果证书已被吊销则返回 true
 */
async function isCertRevoked(cert) {
    const { extensions } = cert;
    if (!extensions) return false;

    let extAuthorityKeyID, extSubjectKeyID, extCRLDistributionPoints, keyIdentifier = undefined;
    extensions.forEach((ext) => {
        if (ext instanceof AuthorityKeyIdentifierExtension) extAuthorityKeyID = ext;
        else if (ext instanceof SubjectKeyIdentifierExtension) extSubjectKeyID = ext;
        else if (ext instanceof CRLDistributionPointsExtension) extCRLDistributionPoints = ext;
    });

    // 检查是否已缓存该 CA 的 CRL 信息
    if (extAuthorityKeyID && extAuthorityKeyID.keyId) keyIdentifier = extAuthorityKeyID.keyId;
    // 可能正在处理自签名的根证书, 此时尝试使用主题密钥标识符扩展
    else if (extSubjectKeyID) keyIdentifier = extSubjectKeyID.keyId;

    if (keyIdentifier) {
        const cached = cacheRevokedCerts[keyIdentifier];
        if (cached) {
            const now = new Date();
            // 如果存在 nextUpdate 字段，确保当前时间尚未超过它
            if (!cached.nextUpdate || cached.nextUpdate > now)
                return cached.revokedCerts.indexOf(cert.serialNumber) >= 0;
        }
    }

    const crlURL = extCRLDistributionPoints?.distributionPoints?.[0].distributionPoint?.fullName?.[0]
        .uniformResourceIdentifier;

    // 如果没有提供 CRL 分发点 URL,则无法进行检查
    if (!crlURL) return false;

    // 下载并解析 CRL
    let certListBytes;
    try {
        const respCRL = await fetch(crlURL);
        certListBytes = await respCRL.arrayBuffer();
    } catch (_err) { return false; } // CRL 格式异常,跳过

    let data;
    try {
        data = new X509Crl(certListBytes);
    } catch (_err) { return false; }

    const newCached = { revokedCerts: [], nextUpdate: undefined }, revokedCerts = data.entries;
    // 记录下次更新时间
    if (data.nextUpdate) newCached.nextUpdate = data.nextUpdate;

    // 收集吊销的证书序列号
    if (revokedCerts) {
        for (const certEntry of revokedCerts) {
            const revokedHex = certEntry.serialNumber;
            newCached.revokedCerts.push(revokedHex);
        }

        if (keyIdentifier) cacheRevokedCerts[keyIdentifier] = newCached; // 缓存结果
        return newCached.revokedCerts.indexOf(cert.serialNumber) >= 0;
    }

    return false;
}

module.exports = { isCertRevoked };