import { AsnParser } from '@peculiar/asn1-schema';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { COSECRV } from '../../cose.js';
import { concat } from '../isoUint8Array.js';

/**
 * 在 WebAuthn 中，EC2 签名被包装在 ASN.1 结构中，因此我们需要从中提取出 r 和 s;
 *
 * 参见 https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
 */
function unwrapEC2Signature(signature, crv) {
    const parsedSignature = AsnParser.parse(signature, ECDSASigValue),
        rBytes = new Uint8Array(parsedSignature.r), sBytes = new Uint8Array(parsedSignature.s),
        componentLength = getSignatureComponentLength(crv),
        rNormalizedBytes = toNormalizedBytes(rBytes, componentLength),
        sNormalizedBytes = toNormalizedBytes(sBytes, componentLength),
        finalSignature = concat([rNormalizedBytes, sNormalizedBytes,]);
    return finalSignature;
}

/**
 * SubtleCrypto Web Crypto API 要求 ECDSA 签名的 `r` 和 `s` 值根据曲线阶数编码为特定的长度;
 * 此函数返回每个签名分量（`r` 和 `s`）所期望的字节长度;
 *
 * 参见 <https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations>
 */
function getSignatureComponentLength(crv) {
    switch (crv) {
        case COSECRV.P256:
            return 32;
        case COSECRV.P384:
            return 48;
        case COSECRV.P521:
            return 66;
        default: throw new Error(`非预期的 COSE crv 值 ${crv} (EC2)`);
    }
}

/**
 * 将 ASN.1 整数表示转换为指定长度 `n` 的字节序列。
 *
 * DER 将整数编码为大端字节数组，采用尽可能小的表示，并且需要一个前导 `0` 字节来区分负数和正数。
 * 这意味着 `r` 和 `s` 的字节长度可能不是 SubtleCrypto Web Crypto API 所期望的长度：
 * 如果存在前导 `0`，则可能比预期短；如果存在前导 `1` 位，则可能长一个字节。
 *
 * 参见 <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
 * 参见 <https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations>
 */
function toNormalizedBytes(bytes, componentLength) {
    let normalizedBytes;
    // 如果字节长度短于预期，需要用前导 `0` 进行填充。
    if (bytes.length < componentLength)
        normalizedBytes = new Uint8Array(componentLength), normalizedBytes.set(bytes, componentLength - bytes.length);
    else if (bytes.length === componentLength) normalizedBytes = bytes;
    // 字节包含一个前导 `0` 用于表示该整数为正数;为了与 SubtleCrypto Web Crypto API 兼容,需要移除这个前导 `0`;
    else if (bytes.length === componentLength + 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0x80)
        normalizedBytes = bytes.subarray(1);
    else throw new Error(`无效的签名分量长度 ${bytes.length}，期望为 ${componentLength}`);

    return normalizedBytes;
}

export { unwrapEC2Signature };