'use strict';

const { getRandomValues } = require('./iso/isoCrypto/index.js'),
    /**
     * 使测试期间能够模拟返回值
     * @ignore 此注释不包含在文档输出中
     */
    _generateUserIDInternals = { stubThis: value => value }

/**
 * 生成一个足够随机的值,用作用户标识符
 *
 * @returns {Promise<string>} 返回 base64url 编码后的用户 ID
 */
async function generateUserID() {
    /**
     * WebAuthn 规范规定 user.id 最大长度为 64 字节,我更喜欢 32 字节随机数经过
     * base64url 编码后的外观,所以这里选用 32 字节;
     */
    const newUserID = new Uint8Array(32);
    await getRandomValues(newUserID);
    return _generateUserIDInternals.stubThis(newUserID);
}

module.exports = { generateUserID, _generateUserIDInternals };