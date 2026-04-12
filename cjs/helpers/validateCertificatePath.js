'use strict';

const { X509Certificate } = require('@peculiar/x509'), { isCertRevoked } = require('./isCertRevoked.js'),
    { getWebCrypto } = require('./iso/isoCrypto/getWebCrypto.js');

/**
 * 遍历 PEM 格式的证书数组，确保它们构成一条合法的证书链
 * @param {string[]} x5cCertsPEM 通常是 `x5c.map(convertASN1toPEM)` 的结果
 * @param {string[]} trustAnchorsPEM PEM 格式的信任锚证书，验证声明中的 x5c 最终需回溯到其中之一
 * @returns {Promise<boolean>}
 */
async function validateCertificatePath(x5cCertsPEM, trustAnchorsPEM = []) {
    // 没有提供任何信任锚，无法进行路径验证，直接返回 true（跳过验证）
    if (trustAnchorsPEM.length === 0) return true;

    const WebCrypto = await getWebCrypto(),
        x5cCertsParsed = x5cCertsPEM.map((certPEM) => new X509Certificate(certPEM)); // 准备解析 x5c 证书

    // 检查 x5c 中是否存在已过期或时效性无效的证书
    for (let i = 0; i < x5cCertsParsed.length; i++) {
        const cert = x5cCertsParsed[i], certPEM = x5cCertsPEM[i];

        try {
            await assertCertNotRevoked(cert);
        } catch (_err) {
            throw new Error(`在 x5c 中发现被吊销的证书：\n${certPEM}`);
        }

        try {
            assertCertIsWithinValidTimeWindow(cert.notBefore, cert.notAfter);
        } catch (_err) {
            throw new Error(`在 x5c 中发现超出有效期的证书：\n${certPEM}`);
        }
    }

    // 准备解析信任锚证书
    const trustAnchorsParsed = trustAnchorsPEM.map((certPEM) => {
        try {
            return new X509Certificate(certPEM);
        } catch (err) {
            throw new Error(`无法解析信任锚证书：\n${certPEM}`, { cause: err });
        }
    }), validTrustAnchors = [];

    // 过滤出未被吊销且时间有效的信任锚
    for (let i = 0; i < trustAnchorsParsed.length; i++) {
        const cert = trustAnchorsParsed[i];
        try {
            await assertCertNotRevoked(cert);
        } catch (_err) { continue; } // 忽略无效证书,继续处理其他锚点

        try {
            assertCertIsWithinValidTimeWindow(cert.notBefore, cert.notAfter);
        } catch (_err) { continue; }

        validTrustAnchors.push(cert);
    }
    if (validTrustAnchors.length === 0) throw new Error('所有指定的信任锚均无效,无法验证 x5c');

    // 尝试用每一个信任锚验证 x5c 链
    let invalidSubjectAndIssuerError = false;
    for (const anchor of trustAnchorsParsed) {
        try {
            const x5cWithTrustAnchor = x5cCertsParsed.concat([anchor]);
            if (new Set(x5cWithTrustAnchor).size !== x5cWithTrustAnchor.length)
                throw new Error('无效的证书路径：发现重复证书');

            // 验证签名及有效期
            for (let i = 0; i < x5cWithTrustAnchor.length - 1; i++) {
                const subject = x5cWithTrustAnchor[i], issuer = x5cWithTrustAnchor[i + 1],
                    // 叶证书或中间证书：确保证书链中的下一级证书对其进行了签名
                    issuerSignedSubject = await subject.verify(
                        { publicKey: issuer.publicKey, signatureOnly: true }, WebCrypto
                    );

                if (!issuerSignedSubject) throw new InvalidSubjectAndIssuer();
                if (issuer.subject === issuer.issuer) {
                    // 检测到根证书，确认其为自签名
                    const issuerSignedIssuer = await issuer.verify(
                        { publicKey: issuer.publicKey, signatureOnly: true }, WebCrypto
                    );
                    if (!issuerSignedIssuer) throw new InvalidSubjectAndIssuer();

                    break; // 遇到根证书后不再继续处理后续证书
                }
            }

            // 成功验证路径,清除之前可能遗留的错误标志,并跳出循环
            invalidSubjectAndIssuerError = false;
            break;
        } catch (err) {
            if (err instanceof InvalidSubjectAndIssuer) invalidSubjectAndIssuerError = true;
            else throw new Error('验证证书路径时发生意外错误', { cause: err });
        }
    }

    // 所有信任锚均验证失败
    if (invalidSubjectAndIssuerError) throw new InvalidSubjectAndIssuer();

    return true;
}

/**
 * 检查证书是否已被吊销，若已吊销则抛出错误
 * @param {X509Certificate} certificate
 */
async function assertCertNotRevoked(certificate) {
    const subjectCertRevoked = await isCertRevoked(certificate);
    if (subjectCertRevoked) throw new Error('在证书路径中发现证书被吊销');
}

/**
 * 要求证书必须处于其 notBefore 与 notAfter 时间窗口内
 * @param {Date} certNotBefore
 * @param {Date} certNotAfter
 */
function assertCertIsWithinValidTimeWindow(certNotBefore, certNotAfter) {
    const now = new Date(Date.now());
    if (certNotBefore > now || certNotAfter < now) throw new Error('证书尚未生效或已过期');
}

// 自定义错误类型,便于区分签名者/主题不匹配的错误
class InvalidSubjectAndIssuer extends Error {
    constructor() {
        const message = '证书的主题颁发者与颁发者主题不匹配';
        super(message), this.name = 'InvalidSubjectAndIssuer';
    }
}

module.exports = { validateCertificatePath };