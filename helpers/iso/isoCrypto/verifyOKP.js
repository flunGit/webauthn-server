import { COSECRV, COSEKEYS, isCOSEAlg } from '../../cose.js';
import { fromBuffer } from '../isoBase64URL.js';
import { importKey } from './importKey.js';
import { getWebCrypto } from './getWebCrypto.js';

/**
 * 验证 OKP（Octet Key Pair）类型的 COSE 签名
 */
async function verifyOKP(opts) {
    const { cosePublicKey, signature, data } = opts, WebCrypto = await getWebCrypto(),
        alg = cosePublicKey.get(COSEKEYS.alg), crv = cosePublicKey.get(COSEKEYS.crv), x = cosePublicKey.get(COSEKEYS.x);

    if (!alg) throw new Error('公钥缺少 alg 字段 (OKP)');
    if (!isCOSEAlg(alg)) throw new Error(`公钥包含无效的 alg 值 ${alg} (OKP)`);
    if (!crv) throw new Error('公钥缺少 crv 字段 (OKP)');
    if (!x) throw new Error('公钥缺少 x 字段 (OKP)');

    // 密钥导入步骤参考：
    // https://wicg.github.io/webcrypto-secure-curves/#ed25519-operations
    let _crv;
    if (crv === COSECRV.ED25519) _crv = 'Ed25519';
    else throw new Error(`不支持的 COSE crv 值 ${crv} (OKP)`);

    const keyData = {
        kty: 'OKP', crv: _crv, alg: 'EdDSA', x: fromBuffer(x), ext: false,
    },
        keyAlgorithm = { name: _crv, namedCurve: _crv },
        key = await importKey({ keyData, algorithm: keyAlgorithm }),
        verifyAlgorithm = { name: _crv };

    return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

export { verifyOKP };