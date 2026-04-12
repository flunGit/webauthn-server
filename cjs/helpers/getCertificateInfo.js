'use strict';

const { AsnParser } = require('@peculiar/asn1-schema'),
    { Certificate, BasicConstraints, id_ce_basicConstraints } = require('@peculiar/asn1-x509'),

    // 用于将 OID 映射为易读的属性名的查找表
    issuerSubjectIDKey = {
        '2.5.4.6': 'C',   // 国家
        '2.5.4.10': 'O',  // 组织
        '2.5.4.11': 'OU', // 组织单位
        '2.5.4.3': 'CN',  // 通用名称
    };

/**
 * 将颁发者或主题的各个部分拼接为字符串，以便于比较颁发者主题与主题颁发者
 *
 * 拼接顺序看似随意，但只要两处使用相同的顺序即可满足比较需求
 *
 * @param {object} input 包含 C、O、OU、CN 等属性的对象
 * @returns {string} 拼接后的字符串
 */
function issuerSubjectToString(input) {
    const parts = [];
    if (input.C) parts.push(input.C);
    if (input.O) parts.push(input.O);
    if (input.OU) parts.push(input.OU);
    if (input.CN) parts.push(input.CN);
    return parts.join(' : ');
}

function processEntity(items, target) {
    items.forEach(([iss]) => {
        const key = issuerSubjectIDKey[iss.type];
        if (key) target[key] = iss.value.toString();
    });
    target.combined = issuerSubjectToString(target);
}

/**
 * 提取 PEM 证书信息
 *
 * @param {ArrayBuffer | Buffer} leafCertBuffer 从 `convertASN1toPEM(x5c[0])` 调用返回的证书二进制数据
 * @returns {object} 解析后的证书信息对象
 */
function getCertificateInfo(leafCertBuffer) {
    // 使用 ASN.1 解析器将二进制证书数据解析为 X.509 结构
    const x509 = AsnParser.parse(leafCertBuffer, Certificate), parsedCert = x509.tbsCertificate,
        issuer = { combined: '' }, subject = { combined: '' };

    // 处理颁发者 (Issuer) 信息和主题 (Subject) 信息
    processEntity(parsedCert.issuer, issuer), processEntity(parsedCert.subject, subject);

    // 检查是否包含基本约束 (Basic Constraints) 扩展,判断是否为 CA 证书
    let basicConstraintsCA = false;
    if (parsedCert.extensions) {
        for (const ext of parsedCert.extensions) {
            if (ext.extnID === id_ce_basicConstraints) {
                const basicConstraints = AsnParser.parse(ext.extnValue, BasicConstraints);
                basicConstraintsCA = basicConstraints.cA;
            }
        }
    }

    // 返回结构化的证书信息
    return {
        issuer, subject, version: parsedCert.version,
        basicConstraintsCA, parsedCertificate: x509,
        notBefore: parsedCert.validity.notBefore.getTime(), notAfter: parsedCert.validity.notAfter.getTime()
    };
}

// 导出
module.exports = { getCertificateInfo };