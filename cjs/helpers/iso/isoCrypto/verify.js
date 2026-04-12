'use strict';

const { isCOSEPublicKeyEC2, isCOSECrv, isCOSEPublicKeyRSA, isCOSEPublicKeyOKP, COSEKEYS } = require('../../cose.js'),
    { verifyEC2 } = require('./verifyEC2.js'), { verifyRSA } = require('./verifyRSA.js'),
    { verifyOKP } = require('./verifyOKP.js'), { unwrapEC2Signature } = require('./unwrapEC2Signature.js');

/**
 * 使用公钥验证签名,支持 EC2 和 RSA 公钥;
 */
function verify(opts) {
    const { cosePublicKey, signature, data, shaHashOverride } = opts;

    if (isCOSEPublicKeyEC2(cosePublicKey)) {
        const crv = cosePublicKey.get(COSEKEYS.crv);
        if (!isCOSECrv(crv)) throw new Error(`未知的 COSE 曲线 ${crv}`);

        const unwrappedSignature = unwrapEC2Signature(signature, crv);
        return verifyEC2({ cosePublicKey, signature: unwrappedSignature, data, shaHashOverride });
    }
    else if (isCOSEPublicKeyRSA(cosePublicKey)) return verifyRSA({ cosePublicKey, signature, data, shaHashOverride });
    else if (isCOSEPublicKeyOKP(cosePublicKey)) return verifyOKP({ cosePublicKey, signature, data });

    const kty = cosePublicKey.get(COSEKEYS.kty);
    throw new Error(`此方法不支持使用 kty 为 ${kty} 的公钥进行签名验证`);
}

module.exports = { verify };