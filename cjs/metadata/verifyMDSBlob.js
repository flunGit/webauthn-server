'use strict';

const { parseJWT } = require('./parseJWT.js'), { verifyJWT } = require('./verifyJWT.js'),
    { validateCertificatePath } = require('../helpers/validateCertificatePath.js'),
    { convertCertBufferToPEM } = require('../helpers/convertCertBufferToPEM.js'),
    { convertPEMToBytes } = require('../helpers/convertPEMToBytes.js'),
    { SettingsService } = require('../services/settingsService.js');

/**
 * 对 [FIDO 元数据服务 (MDS)](https://fidoalliance.org/metadata/) 兼容的 Blob 进行真实性和完整性验证，
 * 并提取其中包含的 FIDO2 元数据声明。此方法会发起网络请求（例如 CRL 检查）。
 *
 * @param {string} blob - 从 MDS 服务器（例如 https://mds3.fidoalliance.org）下载的 JWT
 */
async function verifyMDSBlob(blob) {
    // 解析 JWT
    const parsedJWT = parseJWT(blob), header = parsedJWT[0], payload = parsedJWT[1],
        headerCertsPEM = header.x5c.map(convertCertBufferToPEM);

    try {
        // 验证证书链
        const rootCerts = SettingsService.getRootCertificates({ identifier: 'mds' });
        await validateCertificatePath(headerCertsPEM, rootCerts);
    } catch (error) {
        // 根据 FIDO MDS 文档：“如果链无法验证或链中的某个证书被吊销,则忽略该文件”
        throw new Error('BLOB 证书路径无法验证', { cause: error });
    }

    // 验证 BLOB JWT 签名
    const leafCert = headerCertsPEM[0], verified = await verifyJWT(blob, convertPEMToBytes(leafCert));
    // 根据 FIDO MDS 文档：“如果签名无效,FIDO 服务器应忽略该文件”
    if (!verified) throw new Error('BLOB 签名无法验证');

    // 缓存 FIDO2 设备的声明
    const statements = [];
    for (const entry of payload.entries) {
        // 仅缓存包含 `aaguid` 的条目
        if (entry.aaguid && entry.metadataStatement) statements.push(entry.metadataStatement);
    }

    // 将 nextUpdate 属性转换为 Date 对象,以便确定何时重新下载(月份需要从零开始)
    const [year, month, day] = payload.nextUpdate.split('-'),
        parsedNextUpdate = new Date(parseInt(year, 10), parseInt(month, 10) - 1, parseInt(day, 10));

    return { statements, parsedNextUpdate, payload };
}

module.exports = { verifyMDSBlob };