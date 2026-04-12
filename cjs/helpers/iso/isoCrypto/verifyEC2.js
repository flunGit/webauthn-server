'use strict';

const { COSEKEYS, COSECRV } = require('../../cose.js'), { fromBuffer } = require('../isoBase64URL.js'),
    { mapCoseAlgToWebCryptoAlg } = require('./mapCoseAlgToWebCryptoAlg.js'),
    { importKey } = require('./importKey.js'), { getWebCrypto } = require('./getWebCrypto.js');

/**
 * 使用 EC2 公钥验证签名
 */
async function verifyEC2(opts) {
    const { cosePublicKey, signature, data, shaHashOverride } = opts, WebCrypto = await getWebCrypto(),
        // 导入公钥
        alg = cosePublicKey.get(COSEKEYS.alg), crv = cosePublicKey.get(COSEKEYS.crv),
        x = cosePublicKey.get(COSEKEYS.x), y = cosePublicKey.get(COSEKEYS.y);

    if (!alg) throw new Error('公钥缺少 alg 参数 (EC2)');
    if (!crv) throw new Error('公钥缺少 crv 参数 (EC2)');
    if (!x) throw new Error('公钥缺少 x 参数 (EC2)');
    if (!y) throw new Error('公钥缺少 y 参数 (EC2)');

    let _crv;
    if (crv === COSECRV.P256) _crv = 'P-256';
    else if (crv === COSECRV.P384) _crv = 'P-384';
    else if (crv === COSECRV.P521) _crv = 'P-521';
    else throw new Error(`意外的 COSE crv 值：${crv} (EC2)`);

    const keyData = {
        kty: 'EC', crv: _crv,
        x: fromBuffer(x), y: fromBuffer(y), ext: false
    },
        keyAlgorithm = {
            /**
             * 给未来的自己：此处不能使用 `mapCoseAlgToWebCryptoKeyAlgName()`,因为来自真实设备的部分叶子证书
             * 在 `alg` 中指定了 RSA SHA 值（例如 `-257`），这会被映射为 `'RSASSA-PKCS1-v1_5'`;
             * 这里我们始终需要 `'ECDSA'`,因此直接硬编码;
             */
            name: 'ECDSA', namedCurve: _crv
        }, key = await importKey({ keyData, algorithm: keyAlgorithm });

    // 确定用于签名验证的 SHA 算法
    let subtleAlg = mapCoseAlgToWebCryptoAlg(alg);
    if (shaHashOverride) subtleAlg = mapCoseAlgToWebCryptoAlg(shaHashOverride);

    const verifyAlgorithm = { name: 'ECDSA', hash: { name: subtleAlg } };
    return WebCrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}

module.exports = { verifyEC2 };