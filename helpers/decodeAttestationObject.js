import { decodeFirst } from './iso/index.js';

/**
 * 使测试期间能够对返回值进行桩替换
 * - 查看定义:@see {@link _decodeAttestationObjectInternals}
 * @ignore 不要在文档输出中包含此项
 * @type {{ stubThis: <T>(value: T) => T }}
 */
const _decodeAttestationObjectInternals = { stubThis: value => value };
/**
 * 将 AttestationObject 缓冲区转换为普通对象
 * - 查看定义:@see {@link decodeAttestationObject}
 * @param {BufferSource} attestationObject Attestation Object 缓冲区
 * @returns {Record<string, unknown>} 解码后的 Attestation Object 对象
 */
const decodeAttestationObject = attestationObject => {
    return _decodeAttestationObjectInternals.stubThis(decodeFirst(attestationObject));
}

export { _decodeAttestationObjectInternals, decodeAttestationObject };