'use strict';

// 直接解构导入所需成员，消除所有 `_js_1` 后缀和 `(0, fn)` 调用格式
const { AsnParser } = require('@peculiar/asn1-schema'),
    { Certificate, id_ce_subjectAltName, id_ce_extKeyUsage, SubjectAlternativeName, ExtendedKeyUsage }
        = require('@peculiar/asn1-x509'),
    { decodeCredentialPublicKey, toHash, convertCertBufferToPEM, validateCertificatePath, getCertificateInfo,
        verifySignature, isoUint8Array, validateExtFIDOGenCEAAGUID, COSEKEYS, COSEALG, isCOSEAlg, isCOSEPublicKeyRSA,
        isCOSEPublicKeyEC2 } = require('../../../helpers/index.js'), { areEqual, concat } = isoUint8Array,
    { MetadataService } = require('../../../services/metadataService.js'),
    { verifyAttestationWithMetadata } = require('../../../metadata/verifyAttestationWithMetadata.js'),
    { TPM_MANUFACTURERS, TPM_ECC_CURVE_COSE_CRV_MAP, } = require('./constants.js'),
    { parseCertInfo } = require('./parseCertInfo.js'), { parsePubArea } = require('./parsePubArea.js');

/**
 * 验证 TPM 格式的认证声明
 * @param {Object} options - 验证参数
 * @param {string} options.aaguid - 认证器 AAGUID
 * @param {Map} options.attStmt - 认证声明数据结构
 * @param {Uint8Array} options.authData - 认证器数据
 * @param {Uint8Array} options.credentialPublicKey - 凭证公钥（COSE 格式）
 * @param {Uint8Array} options.clientDataHash - 客户端数据哈希
 * @param {Uint8Array[]} options.rootCertificates - 信任的根证书列表
 * @returns {Promise<boolean>} 验证通过返回 true，否则抛出错误
 */
async function verifyAttestationTPM(options) {
    const { aaguid, attStmt, authData, credentialPublicKey, clientDataHash, rootCertificates } = options,
        ver = attStmt.get('ver'), sig = attStmt.get('sig'), alg = attStmt.get('alg'), x5c = attStmt.get('x5c'),
        pubArea = attStmt.get('pubArea'), certInfo = attStmt.get('certInfo');

    // ---------- 结构有效性检查 ----------
    if (ver !== '2.0') throw new Error(`非预期的 ver "${ver}"，应为 "2.0" (TPM)`);
    if (!sig) throw new Error('attStmt 中未提供签名 (TPM)');
    if (!alg) throw new Error('attStmt 未包含 alg (TPM)');
    if (!isCOSEAlg(alg)) throw new Error(`attStmt 包含无效的 alg ${alg} (TPM)`);
    if (!x5c) throw new Error('attStmt 中未提供证书链 (TPM)');
    if (!pubArea) throw new Error('attStmt 未包含 pubArea (TPM)');
    if (!certInfo) throw new Error('attStmt 未包含 certInfo (TPM)');

    // ---------- 解析并验证公钥区域 ----------
    const parsedPubArea = parsePubArea(pubArea), { unique, type: pubType, parameters } = parsedPubArea,
        cosePublicKey = decodeCredentialPublicKey(credentialPublicKey);
    if (pubType === 'TPM_ALG_RSA') {
        if (!isCOSEPublicKeyRSA(cosePublicKey))
            throw new Error(`凭证公钥类型 kty ${cosePublicKey.get(COSEKEYS.kty)} 与 ${pubType} 不匹配 (TPM|RSA)`);

        const n = cosePublicKey.get(COSEKEYS.n), e = cosePublicKey.get(COSEKEYS.e);
        if (!n) throw new Error('COSE 公钥缺少 n (TPM|RSA)');
        if (!e) throw new Error('COSE 公钥缺少 e (TPM|RSA)');
        if (!areEqual(unique, n)) throw new Error('pubArea.unique 与凭证公钥模数 n 不一致 (TPM|RSA)');
        if (!parameters.rsa) throw new Error('解析的 pubArea 类型为 RSA，但缺少 parameters.rsa (TPM|RSA)');

        const eBuffer = e, pubAreaExponent = parameters.rsa.exponent || 65537,
            eSum = eBuffer[0] + (eBuffer[1] << 8) + (eBuffer[2] << 16);
        if (pubAreaExponent !== eSum) throw new Error(`非预期的公钥指数 ${eSum}，应为 ${pubAreaExponent} (TPM|RSA)`);
    } else if (pubType === 'TPM_ALG_ECC') {
        if (!isCOSEPublicKeyEC2(cosePublicKey))
            throw new Error(`凭证公钥类型 kty ${cosePublicKey.get(COSEKEYS.kty)} 与 ${pubType} 不匹配 (TPM|ECC)`);

        const crv = cosePublicKey.get(COSEKEYS.crv), x = cosePublicKey.get(COSEKEYS.x), y = cosePublicKey.get(COSEKEYS.y);
        if (!crv) throw new Error('COSE 公钥缺少 crv (TPM|ECC)');
        if (!x) throw new Error('COSE 公钥缺少 x (TPM|ECC)');
        if (!y) throw new Error('COSE 公钥缺少 y (TPM|ECC)');
        if (!areEqual(unique, concat([x, y])))
            throw new Error('pubArea.unique 与公钥 x|y 拼接值不一致 (TPM|ECC)');
        if (!parameters.ecc) throw new Error('解析的 pubArea 类型为 ECC，但缺少 parameters.ecc (TPM|ECC)');

        const pubAreaCurveID = parameters.ecc.curveID, expectedCrv = TPM_ECC_CURVE_COSE_CRV_MAP[pubAreaCurveID];
        if (expectedCrv !== crv)
            throw new Error(`pubArea曲线ID "${pubAreaCurveID}" 映射为"${expectedCrv}",与凭证公钥crv "${crv}" 不匹配(TPM|ECC)`);
    }
    else throw new Error(`不支持的 pubArea.type "${pubType}" (TPM)`);

    // ---------- 解析并验证 certInfo ----------
    const parsedCertInfo = parseCertInfo(certInfo), { magic, type: certType, attested, extraData } = parsedCertInfo;

    if (magic !== 0xff544347) throw new Error(`非预期的 magic 值 "${magic}",应为 "0xff544347" (TPM)`);
    if (certType !== 'TPM_ST_ATTEST_CERTIFY')
        throw new Error(`非预期的 type "${certType}",应为 "TPM_ST_ATTEST_CERTIFY" (TPM)`);

    const pubAreaHash = await toHash(pubArea, attestedNameAlgToCOSEAlg(attested.nameAlg)),
        attestedName = concat([attested.nameAlgBuffer, pubAreaHash]);
    if (!areEqual(attested.name, attestedName)) throw new Error('certInfo.attested.name与计算值不一致(TPM)');

    const attToBeSigned = concat([authData, clientDataHash]),
        attToBeSignedHash = await toHash(attToBeSigned, alg);
    if (!areEqual(extraData, attToBeSignedHash)) throw new Error('certInfo.extraData与待签名哈希不一致(TPM)');
    // ---------- 验证 AIK 证书 ----------
    if (x5c.length < 1) throw new Error('x5c 证书链为空 (TPM)');

    const leafCertInfo = getCertificateInfo(x5c[0]),
        { basicConstraintsCA, version, subject, notAfter, notBefore } = leafCertInfo;

    if (basicConstraintsCA) throw new Error('AIK 证书的 basicConstraints CA 字段不为 false (TPM)');
    if (version !== 2) throw new Error('证书版本号不为 3（ASN.1 值为 2）(TPM)');
    if (subject.combined.length > 0) throw new Error('证书 subject 字段不为空 (TPM)');

    const now = new Date();
    if (notBefore > now) throw new Error(`证书尚未生效，生效时间 ${notBefore.toString()} (TPM)`);
    if (notAfter < now) throw new Error(`证书已过期，过期时间 ${notAfter.toString()} (TPM)`);

    // ---------- 深入解析证书扩展项 ----------
    const parsedCert = AsnParser.parse(x5c[0], Certificate);
    if (!parsedCert.tbsCertificate.extensions) throw new Error('证书缺少扩展项 (TPM)');

    let subjectAltNamePresent, extKeyUsage;
    for (const ext of parsedCert.tbsCertificate.extensions) {
        if (ext.extnID === id_ce_subjectAltName)
            subjectAltNamePresent = AsnParser.parse(ext.extnValue, SubjectAlternativeName);
        else if (ext.extnID === id_ce_extKeyUsage) extKeyUsage = AsnParser.parse(ext.extnValue, ExtendedKeyUsage);
    }

    if (!subjectAltNamePresent) throw new Error('证书缺少 subjectAltName 扩展项 (TPM)');
    if (!subjectAltNamePresent[0]?.directoryName?.[0]?.length) throw new Error('subjectAltName中的directoryName为空(TPM)');

    const { tcgAtTpmManufacturer, tcgAtTpmModel, tcgAtTpmVersion } = getTcgAtTpmValues(subjectAltNamePresent[0].directoryName);
    if (!tcgAtTpmManufacturer || !tcgAtTpmModel || !tcgAtTpmVersion) throw new Error('subjectAltName中TPM信息不完整 (TPM)');
    if (!extKeyUsage) throw new Error('证书缺少 extKeyUsage 扩展项 (TPM)');
    if (!TPM_MANUFACTURERS[tcgAtTpmManufacturer]) throw new Error(`无法识别的 TPM 制造商 "${tcgAtTpmManufacturer}" (TPM)`);
    if (extKeyUsage[0] !== '2.23.133.8.3')
        throw new Error(`非预期的 extKeyUsage "${extKeyUsage[0]}",应为 "2.23.133.8.3" (TPM)`);

    // ---------- 验证 AAGUID 扩展项 ----------
    try {
        await validateExtFIDOGenCEAAGUID(parsedCert.tbsCertificate.extensions, aaguid);
    } catch (err) { throw new Error(`${err.message} (TPM)`); }

    // ---------- 证书链验证（优先使用元数据） ----------
    const statement = await MetadataService.getStatement(aaguid);
    if (statement) {
        try {
            await verifyAttestationWithMetadata({ statement, credentialPublicKey, x5c, attestationStatementAlg: alg });
        } catch (err) { throw new Error(`${err.message} (TPM)`); }
    } else {
        try {
            await validateCertificatePath(x5c.map(convertCertBufferToPEM), rootCertificates);
        } catch (err) { throw new Error(`${err.message} (TPM)`); }
    }

    // ---------- 最终签名验证 ----------
    return verifySignature({ signature: sig, data: certInfo, x509Certificate: x5c[0], hashAlgorithm: alg });
}

/**
 * 从 subjectAltName 扩展项的 directoryName 中提取 TCG 定义的 TPM 属性
 */
function getTcgAtTpmValues(root) {
    const OID_MANUFACTURER = '2.23.133.2.1', OID_MODEL = '2.23.133.2.2', OID_VERSION = '2.23.133.2.3';
    let tcgAtTpmManufacturer, tcgAtTpmModel, tcgAtTpmVersion;

    // 兼容两种 ASN.1 结构：每个 RDN 含单个 AttributeTypeAndValue或含多个
    for (const rdn of root) {
        for (const attr of rdn) {
            if (attr.type === OID_MANUFACTURER) tcgAtTpmManufacturer = attr.value.toString();
            else if (attr.type === OID_MODEL) tcgAtTpmModel = attr.value.toString();
            else if (attr.type === OID_VERSION) tcgAtTpmVersion = attr.value.toString();
        }
    }

    return { tcgAtTpmManufacturer, tcgAtTpmModel, tcgAtTpmVersion };
}

/**
 * 将 TPM 内部的哈希算法标识转换为对应的 COSE 算法标识
 */
function attestedNameAlgToCOSEAlg(alg) {
    switch (alg) {
        case 'TPM_ALG_SHA256':
            return COSEALG.ES256;
        case 'TPM_ALG_SHA384':
            return COSEALG.ES384;
        case 'TPM_ALG_SHA512':
            return COSEALG.ES512;
        default:
            throw new Error(`非预期的 TPM 名称算法 ${alg}`);
    }
}

// 导出
module.exports = { verifyAttestationTPM };