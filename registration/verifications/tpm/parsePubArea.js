import { TPM_ALG, TPM_ECC_CURVE } from './constants.js';
import { toDataView, concat } from '../../../helpers/iso/index.js';

/**
 * 解析 TPM 证明中的 pubArea 缓冲区
 * - 查看定义:@see {@link parsePubArea}
 * - 参考规范 12.2.4 TPMT_PUBLIC：
 * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
 *
 * @param {BufferSource} pubArea - 包含 TPMT_PUBLIC 结构的原始字节缓冲区
 * @returns {{
 *   type: string,
 *   nameAlg: string,
 *   objectAttributes: {
 *     fixedTPM: boolean,
 *     stClear: boolean,
 *     fixedParent: boolean,
 *     sensitiveDataOrigin: boolean,
 *     userWithAuth: boolean,
 *     adminWithPolicy: boolean,
 *     noDA: boolean,
 *     encryptedDuplication: boolean,
 *     restricted: boolean,
 *     decrypt: boolean,
 *     signOrEncrypt: boolean
 *   },
 *   authPolicy: Uint8Array,
 *   parameters: {
 *     rsa?: { symmetric: string, scheme: string, keyBits: number, exponent: number },
 *     ecc?: { symmetric: string, scheme: string, curveID: string, kdf: string }
 *   },
 *   unique: Uint8Array
 * }} 解析后的公钥区域结构
 */
const parsePubArea = pubArea => {
    let pointer = 0;
    const dataView = toDataView(pubArea), type = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    const nameAlg = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    // 获取一些身份验证器的属性（？）
    // const objectAttributesInt = pubArea.slice(pointer, (pointer += 4)).readUInt32BE(0);
    const objectAttributesInt = dataView.getUint32(pointer);
    pointer += 4;
    const objectAttributes = {
        fixedTPM: !!(objectAttributesInt & 1),
        stClear: !!(objectAttributesInt & 2),
        fixedParent: !!(objectAttributesInt & 8),
        sensitiveDataOrigin: !!(objectAttributesInt & 16),
        userWithAuth: !!(objectAttributesInt & 32),
        adminWithPolicy: !!(objectAttributesInt & 64),
        noDA: !!(objectAttributesInt & 512),
        encryptedDuplication: !!(objectAttributesInt & 1024),
        restricted: !!(objectAttributesInt & 32768),
        decrypt: !!(objectAttributesInt & 65536),
        signOrEncrypt: !!(objectAttributesInt & 131072),
    };

    // 切出动态长度的 authPolicy
    const authPolicyLength = dataView.getUint16(pointer);
    pointer += 2;
    const authPolicy = pubArea.slice(pointer, pointer += authPolicyLength), parameters = {};
    // 根据类型提取额外的曲线参数
    let unique = Uint8Array.from([]);
    if (type === 'TPM_ALG_RSA') {
        const symmetric = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 2;
        const scheme = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 2;
        const keyBits = dataView.getUint16(pointer);
        pointer += 2;
        const exponent = dataView.getUint32(pointer);
        pointer += 4, parameters.rsa = { symmetric, scheme, keyBits, exponent };

        /**
         * 参考规范 11.2.4.5 TPM2B_PUBLIC_KEY_RSA：
         * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
         */
        // const uniqueLength = pubArea.slice(pointer, (pointer += 2)).readUInt16BE(0);
        const uniqueLength = dataView.getUint16(pointer);
        pointer += 2, unique = pubArea.slice(pointer, pointer += uniqueLength);
    } else if (type === 'TPM_ALG_ECC') {
        const symmetric = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 2;
        const scheme = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 2;
        const curveID = TPM_ECC_CURVE[dataView.getUint16(pointer)];
        pointer += 2;
        const kdf = TPM_ALG[dataView.getUint16(pointer)];
        pointer += 4;

        parameters.ecc = { symmetric, scheme, curveID, kdf };

        /**
         * 参考规范 11.2.5.1 TPM2B_ECC_PARAMETER：
         * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
         */
        // 获取 X
        const uniqueXLength = dataView.getUint16(pointer);
        pointer += 2;
        // 获取 Y
        const uniqueX = pubArea.slice(pointer, pointer += uniqueXLength), uniqueYLength = dataView.getUint16(pointer);
        pointer += 2;
        const uniqueY = pubArea.slice(pointer, pointer += uniqueYLength);
        unique = concat([uniqueX, uniqueY]);
    } else {
        throw new Error(`非预期的类型 "${type}" (TPM)`);
    }

    return { type, nameAlg, objectAttributes, authPolicy, parameters, unique };
};

export { parsePubArea };