import { convertX509PublicKeyToCOSE } from '../helpers/convertX509PublicKeyToCOSE.js';
import { toBuffer, utf8Tobytes } from '../helpers/iso/index.js';
import { isCOSEPublicKeyEC2, isCOSEPublicKeyRSA, COSEKEYS, COSEALG } from '../helpers/cose.js';
import { verifyEC2 } from '../helpers/iso/isoCrypto/verifyEC2.js';
import { verifyRSA } from '../helpers/iso/isoCrypto/verifyRSA.js';

/**
 * 针对 FIDO MDS JWT 的轻量级验证,支持 EC2 和 RSA 算法;
 *
 * 如果需要支持更多 JWS 算法,可参考以下列表：
 *
 * https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1
 *
 * （摘自 https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1）
 */
const verifyJWT = (jwt, leafCert) => {
    const [header, payload, signature] = jwt.split('.'), certCOSE = convertX509PublicKeyToCOSE(leafCert),
        data = utf8Tobytes(`${header}.${payload}`), signatureBytes = toBuffer(signature);

    if (isCOSEPublicKeyEC2(certCOSE))
        return verifyEC2({ data, signature: signatureBytes, cosePublicKey: certCOSE, shaHashOverride: COSEALG.ES256 });
    else if (isCOSEPublicKeyRSA(certCOSE)) return verifyRSA({ data, signature: signatureBytes, cosePublicKey: certCOSE });

    const kty = certCOSE.get(COSEKEYS.kty);
    throw new Error(`此方法不支持使用 kty 为 ${kty} 的公钥进行 JWT 验证`);
};

export { verifyJWT };