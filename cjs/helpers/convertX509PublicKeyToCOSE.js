'use strict';

const { AsnParser } = require('@peculiar/asn1-schema'), { Certificate } = require('@peculiar/asn1-x509'),
    { id_ecPublicKey, id_secp256r1, id_secp384r1, ECParameters } = require('@peculiar/asn1-ecc'),
    { id_rsaEncryption, RSAPublicKey } = require('@peculiar/asn1-rsa'), { COSEKEYS, COSEKTY, COSECRV } = require('./cose.js'),
    { mapX509SignatureAlgToCOSEAlg } = require('./mapX509SignatureAlgToCOSEAlg.js');

/**
 * 将 X.509 证书中的公钥转换为 COSE 格式的公钥 Map
 *
 * @param {Uint8Array} x509Certificate DER 编码的 X.509 证书数据
 * @returns {Map} COSE 格式的公钥 Map
 */
function convertX509PublicKeyToCOSE(x509Certificate) {
    let cosePublicKey = new Map();

    /**
     * 从 X.509 证书中提取公钥
     */
    const x509 = AsnParser.parse(x509Certificate, Certificate), { tbsCertificate } = x509,
        { subjectPublicKeyInfo, signature: _tbsSignature } = tbsCertificate,
        signatureAlgorithm = _tbsSignature.algorithm, publicKeyAlgorithmID = subjectPublicKeyInfo.algorithm.algorithm;

    if (publicKeyAlgorithmID === id_ecPublicKey) {
        /**
         * EC2 公钥
         */
        if (!subjectPublicKeyInfo.algorithm.parameters) throw new Error('证书公钥缺少参数（EC2）');

        const ecParameters = AsnParser.parse(
            new Uint8Array(subjectPublicKeyInfo.algorithm.parameters), ECParameters
        ), { namedCurve } = ecParameters;
        let crv = -999;

        if (namedCurve === id_secp256r1) crv = COSECRV.P256;
        else if (namedCurve === id_secp384r1) crv = COSECRV.P384;
        else throw new Error(`证书公钥包含未预期的命名曲线 ${namedCurve} (EC2)`);

        const subjectPublicKey = new Uint8Array(subjectPublicKeyInfo.subjectPublicKey);
        let x, y;
        if (subjectPublicKey[0] === 0x04) {
            let pointer = 1;
            const halfLength = (subjectPublicKey.length - 1) / 2; // 公钥为未压缩格式,将剩余字节均分为两半
            x = subjectPublicKey.slice(pointer, (pointer += halfLength)), y = subjectPublicKey.slice(pointer);
        }
        else throw new Error('TODO: 处理压缩格式的公钥');

        const coseEC2PubKey = new Map();
        coseEC2PubKey.set(COSEKEYS.kty, COSEKTY.EC2), coseEC2PubKey.set(COSEKEYS.crv, crv);
        coseEC2PubKey.set(COSEKEYS.alg, mapX509SignatureAlgToCOSEAlg(signatureAlgorithm));
        coseEC2PubKey.set(COSEKEYS.x, x), coseEC2PubKey.set(COSEKEYS.y, y);
        cosePublicKey = coseEC2PubKey;
    } else if (publicKeyAlgorithmID === id_rsaEncryption) {
        /**
         * RSA 公钥
         */
        const rsaPublicKey = AsnParser.parse(subjectPublicKeyInfo.subjectPublicKey, RSAPublicKey), coseRSAPubKey = new Map();

        coseRSAPubKey.set(COSEKEYS.kty, COSEKTY.RSA);
        coseRSAPubKey.set(COSEKEYS.alg, mapX509SignatureAlgToCOSEAlg(signatureAlgorithm));
        coseRSAPubKey.set(COSEKEYS.n, new Uint8Array(rsaPublicKey.modulus));
        coseRSAPubKey.set(COSEKEYS.e, new Uint8Array(rsaPublicKey.publicExponent));
        cosePublicKey = coseRSAPubKey;
    }
    else throw new Error(`证书公钥包含未预期的算法 ID ${publicKeyAlgorithmID}`);

    return cosePublicKey;
}

module.exports = { convertX509PublicKeyToCOSE };