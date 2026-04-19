import { TPM_ALG, TPM_ST } from './constants.js';
import { toDataView } from '../../../helpers/index.js';

/**
 * 将 TPM 认证信息（certInfo）解析为可读的结构化数据
 * - 查看定义:@see {@link parseCertInfo}
 *
 * @param {BufferSource} certInfo - 原始的 TPM 认证信息（certInfo）字节数据
 * @returns {{
 *   magic: number,
 *   type: string,
 *   qualifiedSigner: Uint8Array,
 *   extraData: Uint8Array,
 *   clockInfo: { clock: Uint8Array, resetCount: number, restartCount: number, safe: boolean },
 *   firmwareVersion: Uint8Array,
 *   attested: {
 *     nameAlg: string,
 *     nameAlgBuffer: Uint8Array,
 *     name: Uint8Array,
 *     qualifiedName: Uint8Array
 *   }
 * }} 解析后的结构化认证信息对象
 */
const parseCertInfo = certInfo => {
    let pointer = 0;
    // 获取魔数常量
    const dataView = toDataView(certInfo), magic = dataView.getUint32(pointer);
    pointer += 4;

    // 确定认证所使用的算法
    const typeBuffer = dataView.getUint16(pointer);
    pointer += 2;
    // 父实体的名称,可忽略
    const type = TPM_ST[typeBuffer], qualifiedSignerLength = dataView.getUint16(pointer);
    pointer += 2;
    const qualifiedSigner = certInfo.slice(pointer, pointer += qualifiedSignerLength),
        // 获取 `attsToBeSigned` 的期望哈希值
        extraDataLength = dataView.getUint16(pointer);
    pointer += 2;
    const extraData = certInfo.slice(pointer, pointer += extraDataLength),
        // 关于 TPM 设备内部时钟的信息,可忽略
        clock = certInfo.slice(pointer, pointer += 8), resetCount = dataView.getUint32(pointer);
    pointer += 4;
    const restartCount = dataView.getUint32(pointer);
    pointer += 4;
    const safe = !!certInfo.slice(pointer, pointer += 1), clockInfo = { clock, resetCount, restartCount, safe },
        // TPM 设备固件版本,被认证的名称
        firmwareVersion = certInfo.slice(pointer, pointer += 8), attestedNameLength = dataView.getUint16(pointer);
    pointer += 2;
    const attestedName = certInfo.slice(pointer, pointer += attestedNameLength),
        attestedNameDataView = toDataView(attestedName),
        qualifiedNameLength = dataView.getUint16(pointer); // 被认证的限定名称,可忽略
    pointer += 2;
    const qualifiedName = certInfo.slice(pointer, pointer += qualifiedNameLength),
        attested = {
            nameAlg: TPM_ALG[attestedNameDataView.getUint16(0)],
            nameAlgBuffer: attestedName.slice(0, 2),
            name: attestedName,
            qualifiedName,
        };

    return { magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion, attested };
};

export { parseCertInfo };