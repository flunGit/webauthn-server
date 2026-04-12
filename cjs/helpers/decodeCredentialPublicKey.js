'use strict';

const { decodeFirst } = require('./iso/isoCBOR.js'),
    /**
     * 测试时可替换返回值以便进行桩测试
     * @ignore 不包含在文档输出中
     */
    _decodeCredentialPublicKeyInternals = { stubThis: value => value };

function decodeCredentialPublicKey(publicKey) {
    return _decodeCredentialPublicKeyInternals.stubThis(decodeFirst(publicKey));
}

module.exports = { decodeCredentialPublicKey, _decodeCredentialPublicKeyInternals };