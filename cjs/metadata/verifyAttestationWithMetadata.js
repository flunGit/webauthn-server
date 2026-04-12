'use strict';

const { convertCertBufferToPEM } = require('../helpers/convertCertBufferToPEM.js'),
    { validateCertificatePath } = require('../helpers/validateCertificatePath.js'),
    { decodeCredentialPublicKey } = require('../helpers/decodeCredentialPublicKey.js'),
    { COSEKEYS, COSEKTY, isCOSEPublicKeyEC2 } = require('../helpers/cose.js'),

    /**
     * 将 ALG_SIGN 值映射为 COSE 信息
     *
     * 数值定义来自 FIDO 预定义值注册表内的 `ALG_KEY_COSE` 定义
     *
     * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms
     */
    algSignToCOSEInfoMap = {
        secp256r1_ecdsa_sha256_raw: { kty: 2, alg: -7, crv: 1 },
        secp256r1_ecdsa_sha256_der: { kty: 2, alg: -7, crv: 1 },
        rsassa_pss_sha256_raw: { kty: 3, alg: -37 },
        rsassa_pss_sha256_der: { kty: 3, alg: -37 },
        secp256k1_ecdsa_sha256_raw: { kty: 2, alg: -47, crv: 8 },
        secp256k1_ecdsa_sha256_der: { kty: 2, alg: -47, crv: 8 },
        rsassa_pss_sha384_raw: { kty: 3, alg: -38 },
        rsassa_pkcsv15_sha256_raw: { kty: 3, alg: -257 },
        rsassa_pkcsv15_sha384_raw: { kty: 3, alg: -258 },
        rsassa_pkcsv15_sha512_raw: { kty: 3, alg: -259 },
        rsassa_pkcsv15_sha1_raw: { kty: 3, alg: -65535 },
        secp384r1_ecdsa_sha384_raw: { kty: 2, alg: -35, crv: 2 },
        secp512r1_ecdsa_sha256_raw: { kty: 2, alg: -36, crv: 3 },
        ed25519_eddsa_sha512_raw: { kty: 1, alg: -8, crv: 6 },
    };

/**
 * 辅助函数：格式化 COSEInfo 输出,使其比 JSON.stringify() 更美观一些
 *
 * 输入示例：`{ "kty": 3, "alg": -257 }`
 * 输出示例：`"{ kty: 3, alg: -257 }"`
 */
function stringifyCOSEInfo(info) {
    const { kty, alg, crv } = info;
    if (kty !== COSEKTY.RSA) return `{ kty: ${kty}, alg: ${alg}, crv: ${crv} }`;
    else return `{ kty: ${kty}, alg: ${alg} }`;
}

/**
 * 根据 FIDO 联盟元数据服务注册的预期值，匹配认证器证明语句中的各项属性
 */
async function verifyAttestationWithMetadata({ statement, credentialPublicKey, x5c, attestationStatementAlg }) {
    const { authenticationAlgorithms, authenticatorGetInfo, attestationRootCertificates } = statement,
        keypairCOSEAlgs = new Set(), decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey),
        kty = decodedPublicKey.get(COSEKEYS.kty), alg = decodedPublicKey.get(COSEKEYS.alg);

    // 确保证明语句中的算法属于元数据中允许的算法之一
    authenticationAlgorithms.forEach((algSign) => {
        const algSignCOSEINFO = algSignToCOSEInfoMap[algSign];
        if (algSignCOSEINFO) keypairCOSEAlgs.add(algSignCOSEINFO);
    });

    if (!kty) throw new Error('凭证公钥缺少 kty 字段');
    if (!alg) throw new Error('凭证公钥缺少 alg 字段');

    const publicKeyCOSEInfo = { kty, alg };
    if (isCOSEPublicKeyEC2(decodedPublicKey)) {
        const crv = decodedPublicKey.get(COSEKEYS.crv);
        publicKeyCOSEInfo.crv = crv;
    }

    /**
     * 尝试将凭证公钥的算法与设备元数据中指定的算法之一进行匹配
     */
    let foundMatch = false;
    for (const keypairAlg of keypairCOSEAlgs) {
        // 确保算法和密钥类型匹配
        if (keypairAlg.alg === publicKeyCOSEInfo.alg && keypairAlg.kty === publicKeyCOSEInfo.kty) {
            // 对于椭圆曲线或 OKP 密钥,必须曲线编号一致,曲线不匹配时不设置 foundMatch（保持 false）
            const isEcOrOkp = (keypairAlg.kty === COSEKTY.EC2 || keypairAlg.kty === COSEKTY.OKP),
                curveMatches = isEcOrOkp ? (keypairAlg.crv === publicKeyCOSEInfo.crv) : true;
            if (curveMatches) foundMatch = true; // RSA 或其他类型的密钥,直接认为匹配
        }
        if (foundMatch) break;
    }

    if (!foundMatch) {
        const debugMDSAlgs = authenticationAlgorithms.map(
            algSign => `'${algSign}' (COSE 信息: ${stringifyCOSEInfo(algSignToCOSEInfoMap[algSign])})`
        ), strMDSAlgs = JSON.stringify(debugMDSAlgs, null, 2).replace(/"/g, ''),
            strPubKeyAlg = stringifyCOSEInfo(publicKeyCOSEInfo);
        throw new Error(`公钥参数 ${strPubKeyAlg} 未能匹配以下元数据算法中的任意一项：\n${strMDSAlgs}`);
    }

    /**
     * 根据元数据确认证明语句中的算法是受支持的
     */
    if (attestationStatementAlg !== undefined && authenticatorGetInfo?.algorithms !== undefined) {
        const getInfoAlgs = authenticatorGetInfo.algorithms.map(_alg => _alg.alg);
        if (getInfoAlgs.indexOf(attestationStatementAlg) < 0)
            throw new Error(`证明语句中的算法 ${attestationStatementAlg} 不在元数据允许的算法列表 [${getInfoAlgs}] 中`);
    }

    // 准备校验证书链
    const authenticatorCerts = x5c.map(convertCertBufferToPEM),
        statementRootCerts = attestationRootCertificates.map(convertCertBufferToPEM);

    /**
     * 若认证器在 x5c 中只返回了一个证书，并且该证书恰好存在于元数据声明中，
     * 则认为认证器是“自我引用”的，此时跳过证书链校验。
     */
    let authenticatorIsSelfReferencing = false;
    if (authenticatorCerts.length === 1 && statementRootCerts.indexOf(authenticatorCerts[0]) >= 0)
        authenticatorIsSelfReferencing = true;

    if (!authenticatorIsSelfReferencing) {
        try {
            await validateCertificatePath(authenticatorCerts, statementRootCerts);
        } catch (err) {
            throw new Error(`无法使用任何元数据根证书验证证书链：${err.message}`);
        }
    }

    return true;
}

// 集中导出模块接口
module.exports = { algSignToCOSEInfoMap, verifyAttestationWithMetadata };