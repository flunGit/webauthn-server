import {
    toHash, verifySignature, getCertificateInfo, validateCertificatePath, convertCertBufferToPEM, bytesToUtf8, concat,
    utf8Tobytes, b64urlToUtf8, fromBuffer, toBuffer
} from '../../helpers/index.js';
import { MetadataService } from '../../services/metadataService.js';
import { verifyAttestationWithMetadata } from '../../metadata/verifyAttestationWithMetadata.js';

/**
 * 验证格式为 'android-safetynet' 的 attestation 响应
 * - 查看定义:@see {@link verifyAttestationAndroidSafetyNet}
 */
const verifyAttestationAndroidSafetyNet = async options => {
    const {
        attStmt, clientDataHash, authData, aaguid, rootCertificates,
        verifyTimestampMS = true, credentialPublicKey, attestationSafetyNetEnforceCTSCheck,
    } = options, alg = attStmt.get('alg'), response = attStmt.get('response'), ver = attStmt.get('ver');

    if (!ver) throw new Error('attStmt 中缺少 ver 值 (SafetyNet)');
    if (!response) throw new Error('authenticator 的 attStmt 中未包含 response (SafetyNet)');

    // 准备验证 JWT
    const jwt = bytesToUtf8(response), jwtParts = jwt.split('.'),
        HEADER = JSON.parse(b64urlToUtf8(jwtParts[0])),
        PAYLOAD = JSON.parse(b64urlToUtf8(jwtParts[1])), SIGNATURE = jwtParts[2],

        /**
         * 开始验证 PAYLOAD
         */
        { nonce, ctsProfileMatch, timestampMs } = PAYLOAD;
    if (verifyTimestampMS) {
        // 确保时间戳是过去的时刻
        let now = Date.now();
        if (timestampMs > Date.now()) throw new Error(`载荷时间戳 "${timestampMs}" 晚于当前时间 "${now}" (SafetyNet)`);

        // SafetyNet attestation 在它执行后一分钟内视为有效
        const timestampPlusDelay = timestampMs + 60 * 1000;
        now = Date.now();
        if (timestampPlusDelay < now) throw new Error(`载荷时间戳 "${timestampPlusDelay}" 已过期 (SafetyNet)`);
    }

    const nonceBase = concat([authData, clientDataHash]),
        nonceBuffer = await toHash(nonceBase), expectedNonce = fromBuffer(nonceBuffer, 'base64');

    if (nonce !== expectedNonce) throw new Error('无法验证载荷 nonce 值 (SafetyNet)');
    if (attestationSafetyNetEnforceCTSCheck && !ctsProfileMatch) throw new Error('无法验证设备完整性 (SafetyNet)');

    /**
     * 结束验证 PAYLOAD
     */

    /**
     * 开始验证 Header
     */
    // `HEADER.x5c[0]` 肯定是 base64 字符串
    const leafCertBuffer = toBuffer(HEADER.x5c[0], 'base64'),
        leafCertInfo = getCertificateInfo(leafCertBuffer), { subject } = leafCertInfo;

    // 确保证书颁发给了此主机名
    // 参见 https://developer.android.com/training/safetynet/attestation#verify-attestation-response
    if (subject.CN !== 'attest.android.com') throw new Error('证书通用名称不是 "attest.android.com" (SafetyNet)');

    const statement = await MetadataService.getStatement(aaguid);
    if (statement) {
        try {
            await verifyAttestationWithMetadata({
                statement, credentialPublicKey, x5c: HEADER.x5c, attestationStatementAlg: alg
            });
        } catch (err) {
            throw new Error(`${err.message} (SafetyNet)`);
        }
    } else {
        try {
            // 尝试使用通过 SettingsService 设置的根证书验证证书链
            await validateCertificatePath(HEADER.x5c.map(convertCertBufferToPEM), rootCertificates);
        } catch (err) {
            throw new Error(`${err.message} (SafetyNet)`);
        }
    }

    /**
     * 结束验证 Header
     */

    /**
     * 开始验证 Signature
     */
    const signatureBaseBuffer = utf8Tobytes(`${jwtParts[0]}.${jwtParts[1]}`),
        signatureBuffer = toBuffer(SIGNATURE),
        verified = await verifySignature({
            signature: signatureBuffer, data: signatureBaseBuffer, x509Certificate: leafCertBuffer
        });
    /**
     * 结束验证 Signature
     */

    return verified;
};

export { verifyAttestationAndroidSafetyNet };