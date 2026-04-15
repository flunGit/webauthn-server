import { convertCertBufferToPEM } from '../helpers/convertCertBufferToPEM.js';
import { validateCertificatePath } from '../helpers/validateCertificatePath.js';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey.js';
import { COSEKEYS, COSEKTY, isCOSEPublicKeyEC2 } from '../helpers/cose.js';



/**
 * 将 ALG_SIGN 值转换为 COSE 信息
 *
 * 值来自 FIDO 预定义值注册表中的 `ALG_KEY_COSE` 定义
 *
 * https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authentication-algorithms
 */
const algSignToCOSEInfoMap = {
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
},

    /**
     * 辅助函数，以比 JSON.stringify() 更友好的方式格式化 COSEInfo
     *
     * 输入：`{ "kty": 3, "alg": -257 }`
     *
     * 输出：`"{ kty: 3, alg: -257 }"`
     */
    stringifyCOSEInfo = info => {
        const { kty, alg, crv } = info;

        let toReturn = '';
        if (kty !== COSEKTY.RSA) toReturn = `{ kty: ${kty}, alg: ${alg}, crv: ${crv} }`;
        else toReturn = `{ kty: ${kty}, alg: ${alg} }`;

        return toReturn;
    },

    /**
     * 将身份验证器的 attestation 陈述中的属性与 FIDO 联盟元数据服务中注册的期望值进行匹配
     */
    verifyAttestationWithMetadata = async ({ statement, credentialPublicKey, x5c, attestationStatementAlg, }) => {
        const {
            authenticationAlgorithms, authenticatorGetInfo, attestationRootCertificates
        } = statement, keypairCOSEAlgs = new Set();
        // 确保 attestation 陈述中的算法与元数据中指定的算法之一匹配
        authenticationAlgorithms.forEach((algSign) => {
            // 将 algSign 字符串映射为 { kty,alg,crv }
            const algSignCOSEINFO = algSignToCOSEInfoMap[algSign];
            // 保留此语句以防 MDS 返回意外内容
            if (algSignCOSEINFO) keypairCOSEAlgs.add(algSignCOSEINFO);
        });

        // 提取用于比较的公钥 COSE 信息
        const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey),
            kty = decodedPublicKey.get(COSEKEYS.kty), alg = decodedPublicKey.get(COSEKEYS.alg);

        if (!kty) throw new Error('凭证公钥缺少 kty');
        if (!alg) throw new Error('凭证公钥缺少 alg');
        if (!kty) throw new Error('凭证公钥缺少 kty');

        // 假设所有值都是数字，因为这些值应该如此
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

        // 确保公钥属于允许的算法之一
        if (!foundMatch) {
            /**
             * 根据 MDS 算法生成有用的错误输出
             *
             * 示例：
             *
             * ```
             * [
             *   'rsassa_pss_sha256_raw' (COSE 信息: { kty: 3, alg: -37 }),
             *   'secp256k1_ecdsa_sha256_raw' (COSE 信息: { kty: 2, alg: -47, crv: 8 })
             * ]
             * ```
             */
            const debugMDSAlgs = authenticationAlgorithms.map(
                algSign => `'${algSign}' (COSE 信息: ${stringifyCOSEInfo(algSignToCOSEInfoMap[algSign])})`,
            ), strMDSAlgs = JSON.stringify(debugMDSAlgs, null, 2).replace(/"/g, ''),
                strPubKeyAlg = stringifyCOSEInfo(publicKeyCOSEInfo); // 构造关于公钥的错误输出

            throw new Error(`公钥参数 ${strPubKeyAlg} 与以下任何元数据算法均不匹配：\n${strMDSAlgs}`);
        }

        /**
         * 确认 attestation 陈述的算法是元数据支持的算法之一
         */
        if (attestationStatementAlg !== undefined && authenticatorGetInfo?.algorithms !== undefined) {
            const getInfoAlgs = authenticatorGetInfo.algorithms.map((_alg) => _alg.alg);
            if (getInfoAlgs.indexOf(attestationStatementAlg) < 0)
                throw new Error(`Attestation 陈述算法 ${attestationStatementAlg} 与 ${getInfoAlgs} 中的任何一个均不匹配`);
        }

        // 准备检查证书链
        const authenticatorCerts = x5c.map(convertCertBufferToPEM),
            statementRootCerts = attestationRootCertificates.map(convertCertBufferToPEM);

        /**
         * 如果身份验证器在其 x5c 中恰好返回一个证书，并且该证书在元数据陈述中，
         * 则该身份验证器是“自引用的”。在这种情况下，我们跳过证书链验证。
         */
        let authenticatorIsSelfReferencing = false;
        if (authenticatorCerts.length === 1 && statementRootCerts.indexOf(authenticatorCerts[0]) >= 0)
            authenticatorIsSelfReferencing = true;
        if (!authenticatorIsSelfReferencing) {
            try {
                await validateCertificatePath(authenticatorCerts, statementRootCerts);
            } catch (err) {
                const _err = err;
                throw new Error(`无法使用任何元数据根证书验证证书链：${_err.message}`);
            }
        }

        return true;
    };

export { verifyAttestationWithMetadata, algSignToCOSEInfoMap };