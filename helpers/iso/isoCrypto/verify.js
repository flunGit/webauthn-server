import { isCOSEPublicKeyEC2, isCOSECrv, isCOSEPublicKeyRSA, isCOSEPublicKeyOKP, COSEKEYS } from '../../cose.js';
import { verifyEC2 } from './verifyEC2.js';
import { verifyRSA } from './verifyRSA.js';
import { verifyOKP } from './verifyOKP.js';
import { unwrapEC2Signature } from './unwrapEC2Signature.js';

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

export { verify };