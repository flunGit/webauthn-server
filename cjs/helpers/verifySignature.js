'use strict';

const { isoCrypto } = require('./iso/index.js'), { decodeCredentialPublicKey } = require('./decodeCredentialPublicKey.js'),
    { convertX509PublicKeyToCOSE } = require('./convertX509PublicKeyToCOSE.js'),
    /**
     * 用于在测试过程中存根返回值
     * @ignore 不包含在文档输出中
     */
    _verifySignatureInternals = { stubThis: value => value };

/**
 * 验证认证器的签名
 *
 * @param {Object} opts 选项
 * @param {Uint8Array} opts.signature 签名数据
 * @param {Uint8Array} opts.data 被签名的原始数据
 * @param {Uint8Array} [opts.credentialPublicKey] 凭证公钥（COSE 格式）
 * @param {Uint8Array} [opts.x509Certificate] X.509 证书（DER 格式）
 * @param {string} [opts.hashAlgorithm] 哈希算法覆盖值
 * @returns {Promise<boolean>} 签名验证结果
 * @throws {Error} 如果公钥参数不合法
 */
function verifySignature(opts) {
    const { signature, data, credentialPublicKey, x509Certificate, hashAlgorithm } = opts;

    if (!x509Certificate && !credentialPublicKey) throw new Error('必须提供 "x509Certificate" 或 "credentialPublicKey" 之一');
    if (x509Certificate && credentialPublicKey) throw new Error('不能同时提供 "x509Certificate" 和 "credentialPublicKey"');

    let cosePublicKey = new Map();
    if (credentialPublicKey) cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
    else if (x509Certificate) cosePublicKey = convertX509PublicKeyToCOSE(x509Certificate);

    // 直接调用内部存根方法,方便测试时替换返回值
    return _verifySignatureInternals.stubThis(
        isoCrypto.verify({ cosePublicKey, signature, data, shaHashOverride: hashAlgorithm })
    );
}

module.exports = { _verifySignatureInternals, verifySignature };