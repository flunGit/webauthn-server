'use strict';

/**
 * 验证 fmt 为 'android-safetynet' 的 attestation 响应
 */
const { toHash, verifySignature, getCertificateInfo, validateCertificatePath, convertCertBufferToPEM, isoUint8Array,
    isoBase64URL } = require('../../helpers/index.js'), { toUTF8String, concat, fromUTF8String } = isoUint8Array,
    { toUTF8String: b64toUTF8, fromBuffer, toBuffer } = isoBase64URL,
    { MetadataService } = require('../../services/metadataService.js'),
    { verifyAttestationWithMetadata } = require('../../metadata/verifyAttestationWithMetadata.js');

/**
 * 验证 android-safetynet 格式的 attestation
 * @param {Object} options - 验证选项
 * @returns {Promise<boolean>} 验证是否通过
 */
async function verifyAttestationAndroidSafetyNet(options) {
    const {
        attStmt, clientDataHash, authData, aaguid, rootCertificates,
        verifyTimestampMS = true, credentialPublicKey, attestationSafetyNetEnforceCTSCheck,
    } = options, alg = attStmt.get('alg'), response = attStmt.get('response'), ver = attStmt.get('ver');

    if (!ver) throw new Error('attStmt 中缺少 ver 值 (SafetyNet)');
    if (!response) throw new Error('认证器返回的 attStmt 中未包含 response (SafetyNet)');

    // 准备解析 JWT
    const jwt = toUTF8String(response), jwtParts = jwt.split('.'),
        HEADER = JSON.parse(b64toUTF8(jwtParts[0])),
        PAYLOAD = JSON.parse(b64toUTF8(jwtParts[1])), SIGNATURE = jwtParts[2],
        /**
         * 第一步：验证 PAYLOAD
         */
        { nonce, ctsProfileMatch, timestampMs } = PAYLOAD;

    if (verifyTimestampMS) {
        // 确保时间戳是过去的时间
        let now = Date.now();
        if (timestampMs > now) throw new Error(`Payload 中的时间戳 "${timestampMs}" 晚于当前时间 "${now}" (SafetyNet)`);

        // SafetyNet 的认证结果在一分钟内视为有效
        const timestampPlusDelay = timestampMs + 60 * 1000;
        now = Date.now();
        if (timestampPlusDelay < now) throw new Error(`Payload 时间戳已过期：${timestampPlusDelay} (SafetyNet)`);
    }

    const nonceBase = concat([authData, clientDataHash]), nonceBuffer = await toHash(nonceBase),
        expectedNonce = fromBuffer(nonceBuffer, 'base64');

    if (nonce !== expectedNonce) throw new Error('无法验证 payload 中的 nonce (SafetyNet)');
    if (attestationSafetyNetEnforceCTSCheck && !ctsProfileMatch) throw new Error('设备完整性检查未通过 (SafetyNet)');

    /**
     * 第二步：验证 Header
     */
    // HEADER.x5c[0] 一定是一个 base64 字符串
    const leafCertBuffer = toBuffer(HEADER.x5c[0], 'base64'),
        leafCertInfo = getCertificateInfo(leafCertBuffer), { subject } = leafCertInfo;

    // 确保证书是颁发给该主机名的
    // 参考：https://developer.android.com/training/safetynet/attestation#verify-attestation-response
    if (subject.CN !== 'attest.android.com') throw new Error('证书的通用名称（CN）不是 "attest.android.com" (SafetyNet)');

    const statement = await MetadataService.getStatement(aaguid);
    if (statement) {
        try {
            await verifyAttestationWithMetadata({
                statement, credentialPublicKey, x5c: HEADER.x5c, attestationStatementAlg: alg
            });
        } catch (err) { throw new Error(`${err.message} (SafetyNet)`); }
    } else {
        try {
            // 尝试使用通过 SettingsService 设置的根证书来验证证书路径
            await validateCertificatePath(HEADER.x5c.map(convertCertBufferToPEM), rootCertificates);
        } catch (err) { throw new Error(`${err.message} (SafetyNet)`); }
    }

    /**
     * 第三步：验证签名
     */
    const signatureBaseBuffer = fromUTF8String(`${jwtParts[0]}.${jwtParts[1]}`),
        signatureBuffer = toBuffer(SIGNATURE),
        verified = await verifySignature({
            signature: signatureBuffer, data: signatureBaseBuffer, x509Certificate: leafCertBuffer
        });

    return verified;
}

// 导出函数
module.exports = { verifyAttestationAndroidSafetyNet };