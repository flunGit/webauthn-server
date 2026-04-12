'use strict';

/**
 * 支持的签名算法列表
 *
 * 包含原始格式（raw）和 DER 格式的各类椭圆曲线数字签名算法（ECDSA）、
 * RSA-PSS 以及 RSA-PKCS#1 v1.5 签名算法
 */
const AlgSign = [
    'secp256r1_ecdsa_sha256_raw', 'secp256r1_ecdsa_sha256_der',
    'rsassa_pss_sha256_raw', 'rsassa_pss_sha256_der',
    'secp256k1_ecdsa_sha256_raw', 'secp256k1_ecdsa_sha256_der',
    'rsassa_pss_sha384_raw',
    'rsassa_pkcsv15_sha256_raw', 'rsassa_pkcsv15_sha384_raw', 'rsassa_pkcsv15_sha512_raw', 'rsassa_pkcsv15_sha1_raw',
    'secp384r1_ecdsa_sha384_raw', 'secp512r1_ecdsa_sha256_raw', 'ed25519_eddsa_sha512_raw',
];

// 导出常量数组
module.exports = { AlgSign };