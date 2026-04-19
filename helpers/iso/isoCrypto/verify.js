import { isCOSEPublicKeyEC2, isCOSECrv, isCOSEPublicKeyRSA, isCOSEPublicKeyOKP, COSEKEYS } from '../../cose.js';
import { verifyEC2 } from './verifyEC2.js';
import { verifyRSA } from './verifyRSA.js';
import { verifyOKP } from './verifyOKP.js';
import { unwrapEC2Signature } from './unwrapEC2Signature.js';

/**
 * 使用 COSE 格式公钥验证签名，支持 EC2、RSA 和 OKP 密钥类型
 * - 查看定义:@see {@link verify}
 * @param {Object} opts - 验证选项
 * @param {Map<number, number | BufferSource>} opts.cosePublicKey - COSE 格式的公钥（包含必要的密钥参数）
 * @param {BufferSource} opts.signature - 待验证的签名（原始 ASN.1 或 COSE 格式）
 * @param {BufferSource} opts.data - 已签名的原始数据
 * @param {string} [opts.shaHashOverride] - 可选，覆盖默认的哈希算法（如 'SHA-256'）
 * @returns {Promise<boolean>} 验证通过返回 true，否则 false
 * @throws {Error} 当公钥类型不支持、曲线未知或签名格式无效时抛出错误
 */
const verify = opts => {
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
};

export { verify };