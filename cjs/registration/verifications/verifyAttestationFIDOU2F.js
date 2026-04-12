'use strict';

const { convertCOSEtoPKCS, convertCertBufferToPEM, validateCertificatePath, verifySignature, isoUint8Array, COSEALG
} = require('../../helpers/index.js'), { concat, toHex } = isoUint8Array;

/**
 * 验证 fmt 为 'fido-u2f' 的证明响应
 */
async function verifyAttestationFIDOU2F(options) {
    const { attStmt, clientDataHash, rpIdHash, credentialID, credentialPublicKey, aaguid, rootCertificates, } = options,
        reservedByte = Uint8Array.from([0x00]), publicKey = convertCOSEtoPKCS(credentialPublicKey),
        signatureBase = concat([reservedByte, rpIdHash, clientDataHash, credentialID, publicKey,]),
        sig = attStmt.get('sig'), x5c = attStmt.get('x5c');

    if (!x5c) throw new Error('证明声明中未提供证明证书 (FIDOU2F)');
    if (!sig) throw new Error('证明声明中未提供证明签名 (FIDOU2F)');

    // FIDO 规范要求此处的 aaguid 必须等于 0x00 才视为合法
    const aaguidToHex = Number.parseInt(toHex(aaguid), 16);
    if (aaguidToHex !== 0x00) throw new Error(`AAGUID "${aaguidToHex}" 不符合预期值 0x00`);

    try {
        // 尝试使用通过 SettingsService 设置的根证书来验证证书链
        await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
    } catch (err) { throw new Error(`${err.message} (FIDOU2F)`); }

    return verifySignature({ signature: sig, data: signatureBase, x509Certificate: x5c[0], hashAlgorithm: COSEALG.ES256 });
}

module.exports = { verifyAttestationFIDOU2F };