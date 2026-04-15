import { decodeFirst } from './iso/isoCBOR.js';

/**
 * 使得在测试期间可以模拟（stub）返回值
 * @ignore 不要在文档输出中包含此项
 */
const _decodeCredentialPublicKeyInternals = { stubThis: value => value },

    decodeCredentialPublicKey = publicKey => {
        return _decodeCredentialPublicKeyInternals.stubThis(decodeFirst(publicKey));
    }

export { _decodeCredentialPublicKeyInternals, decodeCredentialPublicKey };