'use strict';

const { TPM_ALG, TPM_ECC_CURVE } = require('./constants.js'), { toDataView, concat } = require('../../../helpers/iso/isoUint8Array.js');
/**
 * 解析 TPM 认证的 pubArea 缓冲区
 *
 * 参考 12.2.4 TPMT_PUBLIC 章节：
 * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
 */
function parsePubArea(pubArea) {
    let pointer = 0;
    const dataView = toDataView(pubArea), type = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    const nameAlg = TPM_ALG[dataView.getUint16(pointer)];
    pointer += 2;

    // 获取一些认证属性
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
    }, authPolicyLength = dataView.getUint16(pointer); // 切出动态长度的 authPolicy
    pointer += 2;

    // 根据类型提取额外曲线参数
    const authPolicy = pubArea.slice(pointer, pointer += authPolicyLength), parameters = {};
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
         * 参考 11.2.4.5 TPM2B_PUBLIC_KEY_RSA：
         * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
         */
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
        pointer += 2, parameters.ecc = { symmetric, scheme, curveID, kdf };

        /**
         * 参考 11.2.5.1 TPM2B_ECC_PARAMETER：
         * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf
         */
        // 获取 X 坐标
        const uniqueXLength = dataView.getUint16(pointer);
        pointer += 2;

        // 获取 Y 坐标
        const uniqueX = pubArea.slice(pointer, pointer += uniqueXLength), uniqueYLength = dataView.getUint16(pointer);
        pointer += 2;

        const uniqueY = pubArea.slice(pointer, pointer += uniqueYLength);
        unique = concat([uniqueX, uniqueY]);
    }
    else throw new Error(`不支持的 TPM 类型："${type}"`);

    return { type, nameAlg, objectAttributes, authPolicy, parameters, unique };
}

module.exports = { parsePubArea };