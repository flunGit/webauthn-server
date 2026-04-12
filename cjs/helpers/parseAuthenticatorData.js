'use strict';

const { decodeAuthenticatorExtensions } = require('./decodeAuthenticatorExtensions.js'),
    { isoUint8Array, isoCBOR } = require('./iso/index.js'), { toDataView, fromHex, areEqual } = isoUint8Array,
    { decodeFirst, encode } = isoCBOR,
    /**
     * 用于在测试时替换返回值（stub）
     * @ignore 不在文档中输出此内部属性
     */
    _parseAuthenticatorDataInternals = { stubThis: value => value };

/**
 * 解析 Attestation 中包含的 authData 缓冲区
 *
 * @param {Uint8Array} authData 认证器数据
 * @returns {Object} 解析后的数据结构
 */
function parseAuthenticatorData(authData) {
    if (authData.byteLength < 37)
        throw new Error(`Authenticator data 长度为 ${authData.byteLength} 字节,预期至少 37 字节`);

    // RP ID 哈希（32 字节）,标志位（1 字节）,签名计数器（4 字节）
    let pointer = 0;
    const dataView = toDataView(authData), rpIdHash = authData.slice(pointer, (pointer += 32)),
        flagsBuf = authData.slice(pointer, (pointer += 1)), flagsInt = flagsBuf[0],
        // 标志位定义参考：https://www.w3.org/TR/webauthn-2/#flags
        flags = {
            up: !!(flagsInt & (1 << 0)), // 用户存在（User Presence）
            uv: !!(flagsInt & (1 << 2)), // 用户验证（User Verified）
            be: !!(flagsInt & (1 << 3)), // 备份资格（Backup Eligibility）
            bs: !!(flagsInt & (1 << 4)), // 备份状态（Backup State）
            at: !!(flagsInt & (1 << 6)), // 包含认证凭证数据（Attested Credential Data Present）
            ed: !!(flagsInt & (1 << 7)), // 包含扩展数据（Extension Data Present）
            flagsInt,
        }, counterBuf = authData.slice(pointer, pointer + 4), counter = dataView.getUint32(pointer, false);
    pointer += 4;

    let aaguid = undefined, credentialID = undefined, credentialPublicKey = undefined;
    // 如果包含认证凭证数据
    if (flags.at) {
        aaguid = authData.slice(pointer, (pointer += 16)); // AAGUID（16 字节）

        const credIDLen = dataView.getUint16(pointer);     // 凭证 ID 长度（2 字节）
        pointer += 2, credentialID = authData.slice(pointer, (pointer += credIDLen));

        /**
         * Firefox 117 在使用 EdDSA (-8) 公钥时，错误地对 authData 进行了 CBOR 编码。
         * 正确的 CBOR "包含 4 项的 Map"（0xa4）被错误编码为 "包含 3 项的 Map"（0xa3），
         * 如果我们手动修正这一字节，authData 有很大概率能被正确解析。
         *
         * 此浏览器版本还错误地将 "OKP" 和 "Ed25519" 用字符串表示，而不是整数值。
         * 因此下文的十六进制公钥数据看起来会比较奇怪。
         */
        // 这些字节解码后为：{ 1: "OKP", 3: -8, -1: "Ed25519" }（缺少键 -2，即 COSEKEYS.x）
        const badEdDSACBOR = fromHex('a301634f4b500327206745643235353139'),
            bytesAtCurrentPosition = authData.slice(pointer, pointer + badEdDSACBOR.byteLength);
        let foundBadCBOR = false;

        if (areEqual(badEdDSACBOR, bytesAtCurrentPosition))
            // 将错误的 0xa3 改为 0xa4，以便公钥能被识别
            foundBadCBOR = true, authData[pointer] = 0xa4;

        // 解码当前位置的 CBOR 数据，然后重新编码为 Buffer
        const firstDecoded = decodeFirst(authData.slice(pointer)),
            firstEncoded = Uint8Array.from(
                /**
                 * 这里将解码结果强制视为 Map（通过 JS 运行时自然推导），因为 TypeScript 无法为
                 * 每个键值对定义精确类型，且 CBOR 库通常将 Major Type 5 解析为 Map;
                 * COSEPublicKey 可以概括为“键为数字、值为数字或字节的 Map”;
                 * 如果此假设不成立,后续验证步骤会失败,因此在此处做类型假设是安全的;
                 */
                encode(firstDecoded)
            );

        // 恢复我们修改的字节,保证 authData 与输入时一致,避免破坏签名验证
        if (foundBadCBOR) authData[pointer] = 0xa3;

        credentialPublicKey = firstEncoded, pointer += firstEncoded.byteLength;
    }

    let extensionsData = undefined, extensionsDataBuffer = undefined;
    // 如果包含扩展数据
    if (flags.ed) {
        const firstDecoded = decodeFirst(authData.slice(pointer));
        extensionsDataBuffer = Uint8Array.from(encode(firstDecoded));
        extensionsData = decodeAuthenticatorExtensions(extensionsDataBuffer);
        pointer += extensionsDataBuffer.byteLength;
    }

    // 指针应正好位于 authData 末尾,否则说明有多余数据
    if (authData.byteLength > pointer) throw new Error('解析认证器数据时发现多余的字节');

    return _parseAuthenticatorDataInternals.stubThis({
        rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid,
        credentialID, credentialPublicKey, extensionsData, extensionsDataBuffer,
    });
}

// 导出公共 API
module.exports = { parseAuthenticatorData, _parseAuthenticatorDataInternals };