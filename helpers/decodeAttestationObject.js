import { decodeFirst } from './iso/isoCBOR.js';

/**
 * 使测试期间能够对返回值进行桩替换
 * @ignore 不要在文档输出中包含此项
 */
const _decodeAttestationObjectInternals = { stubThis: value => value };
/**
 * 将 AttestationObject 缓冲区转换为普通对象
 *
 * @param attestationObject  Attestation Object 缓冲区
 */
function decodeAttestationObject(attestationObject) {
    return _decodeAttestationObjectInternals.stubThis(decodeFirst(attestationObject));
}

export { _decodeAttestationObjectInternals, decodeAttestationObject };