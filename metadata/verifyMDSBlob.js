import { parseJWT } from './parseJWT.js';
import { verifyJWT } from './verifyJWT.js';
import { validateCertificatePath } from '../helpers/validateCertificatePath.js';
import { convertCertBufferToPEM } from '../helpers/convertCertBufferToPEM.js';
import { convertPEMToBytes } from '../helpers/convertPEMToBytes.js';
import { SettingsService } from '../services/settingsService.js';

/**
 * 对符合 [FIDO 元数据服务 (MDS)](https://fidoalliance.org/metadata/) 规范的 BLOB 进行真实性与完整性验证,
 * 并提取其中包含的 FIDO2 元数据声明,此方法将发起网络请求以执行 CRL 等检查;
 * - 查看定义:@see {@link verifyMDSBlob}
 *
 * @param {string} blob - 从 MDS 服务器下载的 JWT（例如 https://mds3.fidoalliance.org）
 * @returns {Promise<{statements: object[],parsedNextUpdate: Date,payload: object}>}
 *  返回一个对象，包含解析出的元数据声明列表、下次更新时间的 Date 对象以及原始载荷对象
 */
const verifyMDSBlob = async blob => {
    // 解析 JWT
    const parsedJWT = parseJWT(blob), header = parsedJWT[0], payload = parsedJWT[1],
        headerCertsPEM = header.x5c.map(convertCertBufferToPEM);

    try {
        // 验证证书链
        const rootCerts = SettingsService.getRootCertificates({ identifier: 'mds' });
        await validateCertificatePath(headerCertsPEM, rootCerts);
    } catch (error) {
        // 根据 FIDO MDS 文档：“如果证书链无法验证或链中任一证书被吊销,应忽略该文件”
        throw new Error('无法验证 BLOB 证书路径', { cause: error });
    }

    // 验证 BLOB 的 JWT 签名
    const leafCert = headerCertsPEM[0], verified = await verifyJWT(blob, convertPEMToBytes(leafCert));
    if (!verified) throw new Error('无法验证 BLOB 签名'); // 根据 FIDO MDS 文档：“如果签名无效,FIDO 服务器应忽略该文件”

    // 缓存 FIDO2 设备的声明
    const statements = [];
    for (const entry of payload.entries) {
        // 仅缓存包含 `aaguid` 的条目
        if (entry.aaguid && entry.metadataStatement) statements.push(entry.metadataStatement);
    }

    // 将 nextUpdate 属性转换为 Date 对象,以便确定重新下载的时间(月份需要从 0 开始索引)
    const [year, month, day] = payload.nextUpdate.split('-'),
        parsedNextUpdate = new Date(parseInt(year, 10), parseInt(month, 10) - 1, parseInt(day, 10));

    return { statements, parsedNextUpdate, payload };
};

export { verifyMDSBlob };