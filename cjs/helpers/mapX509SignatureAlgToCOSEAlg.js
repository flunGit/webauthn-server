'use strict';

const { COSEALG } = require('./cose.js');

/**
 * 将 X.509 签名算法 OID 映射为 COSE 算法 ID
 *
 * - EC2 OID 参考：https://oidref.com/1.2.840.10045.4.3
 * - RSA OID 参考：https://oidref.com/1.2.840.113549.1.1
 */
function mapX509SignatureAlgToCOSEAlg(signatureAlgorithm) {
    let alg;
    if (signatureAlgorithm === '1.2.840.10045.4.3.2') alg = COSEALG.ES256;
    else if (signatureAlgorithm === '1.2.840.10045.4.3.3') alg = COSEALG.ES384;
    else if (signatureAlgorithm === '1.2.840.10045.4.3.4') alg = COSEALG.ES512;
    else if (signatureAlgorithm === '1.2.840.113549.1.1.11') alg = COSEALG.RS256;
    else if (signatureAlgorithm === '1.2.840.113549.1.1.12') alg = COSEALG.RS384;
    else if (signatureAlgorithm === '1.2.840.113549.1.1.13') alg = COSEALG.RS512;
    else if (signatureAlgorithm === '1.2.840.113549.1.1.5') alg = COSEALG.RS1;
    else throw new Error(`无法将 X.509 签名算法 ${signatureAlgorithm} 映射到 COSE 算法`);

    return alg;
}

module.exports = { mapX509SignatureAlgToCOSEAlg };