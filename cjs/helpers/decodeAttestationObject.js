'use strict';

const { decodeFirst } = require('./iso/isoCBOR.js');
/**
 * 将 AttestationObject 缓冲区转换为标准对象
 *
 * @param {Uint8Array} attestationObject Attestation Object 二进制缓冲区
 * @returns {any} 解码后的认证对象
 */
function decodeAttestationObject(attestationObject) {
    // 使用内部的存根方法包装解码结果,便于测试时替换返回值
    return _decodeAttestationObjectInternals.stubThis(decodeFirst(attestationObject));
}

/**
 * 用于测试期间替换返回值
 * @ignore 不包含在生成的文档中
 */
const _decodeAttestationObjectInternals = { stubThis: value => value };

// 导出公共 API 及内部测试钩子
module.exports = { decodeAttestationObject, _decodeAttestationObjectInternals };