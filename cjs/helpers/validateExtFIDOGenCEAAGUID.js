'use strict';

/**
 * 导入 ASN.1 解析所需的模块
 */
const { AsnParser, OctetString } = require('@peculiar/asn1-schema'), { areEqual, toHex } = require('./iso/isoUint8Array.js'),
    /**
     * 证明证书扩展 OID：`id-fido-gen-ce-aaguid`
     *
     * 来源：https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#verifying-an-attestation-statement
     */
    id_fido_gen_ce_aaguid = '1.3.6.1.4.1.45724.1.1.4';

/**
 * 查找 id-fido-gen-ce-aaguid 证书扩展,如果存在,则与证明声明中的 AAGUID 进行比对校验。
 *
 * @param {Array} certExtensions 证书扩展列表
 * @param {Uint8Array} aaguid 证明声明中的 AAGUID 值
 * @returns {boolean} 校验通过返回 true,否则抛出错误
 */
function validateExtFIDOGenCEAAGUID(certExtensions, aaguid) {
    if (!certExtensions) return true; // 证书无扩展,无需校验

    const extFIDOGenCEAAGUID = certExtensions.find(ext => ext.extnID === id_fido_gen_ce_aaguid);
    // 未找到该扩展，无需校验
    if (!extFIDOGenCEAAGUID) return true;

    // 解析扩展值
    const parsedExtFIDOGenCEAAGUID = AsnParser.parse(extFIDOGenCEAAGUID.extnValue, OctetString),
        extValue = new Uint8Array(parsedExtFIDOGenCEAAGUID.buffer),
        aaguidAndExtAreEqual = areEqual(aaguid, extValue); // 比对两个值是否相等

    if (!aaguidAndExtAreEqual) {
        const _debugExtHex = toHex(extValue), _debugAAGUIDHex = toHex(aaguid);
        throw new Error(
            `证书扩展 id-fido-gen-ce-aaguid (${id_fido_gen_ce_aaguid}) 的值为 "${_debugExtHex}",
            但与证明声明中的 AAGUID 值 "${_debugAAGUIDHex}" 不一致`
        );
    }

    return true;
}

// 导出公共 API
module.exports = { validateExtFIDOGenCEAAGUID };