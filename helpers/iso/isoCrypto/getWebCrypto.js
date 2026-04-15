"use strict";

let webCrypto = undefined;

// 便于在测试时模拟返回值
const _getWebCryptoInternals = {
    stubThisGlobalThisCrypto: () => globalThis.crypto,
    setCachedCrypto: newCrypto => webCrypto = newCrypto, // 便于重置文件顶部的 `webCrypto` 变量
};

/**
 * 尝试从当前运行时获取 Crypto API 的实例,应该支持 Node 以及实现了 Web API 的其他环境（如 Deno）;
 * @returns {Promise<Crypto>} 解析为 Crypto 对象（可通过 .subtle 访问 SubtleCrypto）
 */
function getWebCrypto() {
    /**
     * 你好！如果你来到这里想知道为什么这个方法是异步的,而 `globalThis.crypto` 的访问却是同步的,
     * 这是为了尽量减少与此方法同步化相关的大量重构工作;例如,如果我们将此方法同步化,
     * `generateRegistrationOptions()` 和 `generateAuthenticationOptions()` 也会变成同步的
     * （因为这两个方法中没有其他异步操作）,这将是本库核心 API 的一个破坏性变更;
     *
     * TODO：如果你在 2025 年 2 月之后读到这段注释,请考虑是否还有必要保持此方法为异步;
     */
    const toResolve = new Promise((resolve, reject) => {
        if (webCrypto) return resolve(webCrypto);

        /**
         * 尝试以全局对象的形式访问 Crypto,这种方式被流行基于 ESM 运行（以及 Node v20+）所支持;
         */
        const _globalThisCrypto = _getWebCryptoInternals.stubThisGlobalThisCrypto();
        if (_globalThisCrypto) return webCrypto = _globalThisCrypto, resolve(webCrypto);

        return reject(new MissingWebCrypto()); // 我们已经尝试了在 Node 中和全局访问,都无法获取,因此放弃
    });
    return toResolve;
}

class MissingWebCrypto extends Error {
    constructor() {
        const message = '无法定位 Crypto API 的实例';
        super(message), this.name = 'MissingWebCrypto';
    }
}

export { _getWebCryptoInternals, getWebCrypto, MissingWebCrypto };