/**
 * 支持的签名算法数组
 * - 查看定义:@see {@link AlgSign}
 * @type {string[]}
 * @constant
 * @description
 * 算法命名规则: [曲线/算法]_[签名类型]_[哈希算法]_[编码格式]
 * 其中:
 * - secp256r1, secp256k1, secp384r1, secp512r1: 椭圆曲线
 * - ed25519: EdDSA曲线
 * - rsassa_pss: RSA-PSS填充方案
 * - rsassa_pkcsv1_5: RSA PKCS#1 v1.5填充方案
 * - ecdsa: 椭圆曲线数字签名算法
 * - eddsa: Edwards曲线数字签名算法
 * - sha256, sha384, sha512, sha1: 哈希算法
 * - raw: 原始签名输出（无ASN.1 DER编码）
 * - der: DER编码格式
 */
const AlgSign = [
    'secp256r1_ecdsa_sha256_raw',   // secp256r1曲线，ECDSA，SHA-256，原始格式
    'secp256r1_ecdsa_sha256_der',   // secp256r1曲线，ECDSA，SHA-256，DER编码
    'rsassa_pss_sha256_raw',        // RSA-PSS，SHA-256，原始格式
    'rsassa_pss_sha256_der',        // RSA-PSS，SHA-256，DER编码
    'secp256k1_ecdsa_sha256_raw',   // secp256k1曲线，ECDSA，SHA-256，原始格式
    'secp256k1_ecdsa_sha256_der',   // secp256k1曲线，ECDSA，SHA-256，DER编码
    'rsassa_pss_sha384_raw',        // RSA-PSS，SHA-384，原始格式
    'rsassa_pkcsv15_sha256_raw',    // RSA PKCS#1 v1.5，SHA-256，原始格式
    'rsassa_pkcsv15_sha384_raw',    // RSA PKCS#1 v1.5，SHA-384，原始格式
    'rsassa_pkcsv15_sha512_raw',    // RSA PKCS#1 v1.5，SHA-512，原始格式
    'rsassa_pkcsv15_sha1_raw',      // RSA PKCS#1 v1.5，SHA-1，原始格式
    'secp384r1_ecdsa_sha384_raw',   // secp384r1曲线，ECDSA，SHA-384，原始格式
    'secp512r1_ecdsa_sha256_raw',   // secp512r1曲线，ECDSA，SHA-256，原始格式
    'ed25519_eddsa_sha512_raw',     // Ed25519曲线，EdDSA，SHA-512，原始格式
];

export { AlgSign };