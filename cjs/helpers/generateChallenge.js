'use strict';

const { getRandomValues } = require('./iso/isoCrypto/index.js'),
    /**
     * 便于在测试期间模拟返回值
     * @ignore 不要包含在文档输出中
     */
    _generateChallengeInternals = { stubThis: value => value };

/**
 * 生成一个足够随机的值，用作认证或断言挑战
 */
async function generateChallenge() {
    /**
     * WebAuthn 规范指出 16 字节是一个良好的最小值：
     *
     * "为了防止重放攻击,挑战必须包含足够的熵以使其无法被猜测,因此挑战应至少为 16 字节长;"
     *
     * 为保险起见,我们将其加倍;
     */
    const challenge = new Uint8Array(32);
    await getRandomValues(challenge);
    return _generateChallengeInternals.stubThis(challenge);
}

module.exports = { generateChallenge, _generateChallengeInternals };