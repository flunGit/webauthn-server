import { isoCrypto } from './iso/index.js';
import { decodeCredentialPublicKey } from './decodeCredentialPublicKey.js';
import { convertX509PublicKeyToCOSE } from './convertX509PublicKeyToCOSE.js';

/**
 * 用于在测试时模拟返回值
 * @ignore 不要将此内容包含在文档输出中
 */
const _verifySignatureInternals = { stubThis: value => value };

/**
 * 验证身份验证器的签名
 */
function verifySignature(opts) {
    const { signature, data, credentialPublicKey, x509Certificate, hashAlgorithm, } = opts;
    if (!x509Certificate && !credentialPublicKey) throw new Error('必须声明 "leafCert" 或 "credentialPublicKey" 其中之一');
    if (x509Certificate && credentialPublicKey) throw new Error('不能同时声明 "leafCert" 和 "credentialPublicKey"');
    let cosePublicKey = new Map();
    if (credentialPublicKey) cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
    else if (x509Certificate) cosePublicKey = convertX509PublicKeyToCOSE(x509Certificate);
    return _verifySignatureInternals.stubThis(isoCrypto.verify({
        cosePublicKey, signature, data, shaHashOverride: hashAlgorithm
    }));
}

export { _verifySignatureInternals, verifySignature };